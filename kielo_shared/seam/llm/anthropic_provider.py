"""Anthropic (Claude) messages provider for the Python LLM seam.

Wraps ``anthropic.AsyncAnthropic.messages``. The SDK is an optional dependency
(``pip install kielo-shared[anthropic]``); it is imported only when the provider
builds its own client, so a process that never routes to Claude never loads it.
A caller may inject a client instead (tests, a client with its own pool).

Mapping:

  ``Request.system_prompt``  -> ``system``
  ``Request.prompt``         -> one user message
  ``Request.model``          -> required; the llm route supplies it
  ``Request.response_mime_type="application/json"`` -> a JSON-only line appended
      to the system prompt (Claude has no JSON mode), and a wrapping code fence
      stripped from a one-shot answer
  ``Request.temperature`` / ``response_schema`` -> not sent: current Claude
      models reject sampling parameters

A route's thinking budget is a Gemini token budget. Claude takes an effort level
instead (``claude_effort``): -1 keeps the model's default, up to 1024 asks for
low effort, more for medium. Current Claude models cannot turn thinking off, so
0 is low effort too.

A call that ends in a refusal, or is cut off by ``max_tokens``, raises
``Error(PROVIDER_ERROR, ProviderStopped)``; a call with no key or no SDK raises
``ProviderUnavailable``. Usage (output without thinking, thinking apart) is
reported to ``usage_sink`` after every call that reached the API, also a refused
or truncated one, and, under a ``family``, to the llmroute rollup and the spend
guard.
"""

from __future__ import annotations

import time
from typing import Any, AsyncIterator, Callable, Optional

from kielo_shared import llmroute
from kielo_shared.llm.pricing import estimate_usd
from kielo_shared.llm.spend_guard import admit_paid_call, record_actual_usd
from kielo_shared.seam.llm.types import (
    Error,
    ErrorClass,
    Request,
    Result,
)

DEFAULT_MAX_TOKENS = 16000
DEFAULT_TIMEOUT_SECONDS = 60.0
DEFAULT_MAX_RETRIES = 1

_LOW_EFFORT_MAX_BUDGET = 1024
_REFUSAL = "refusal"
_CUT_OFF = ("max_tokens", "model_context_window_exceeded")
_JSON_ONLY = (
    "Reply with a single JSON object and nothing else: no code fence, no text "
    "before or after it."
)

UsageSink = Callable[[int, int, int], None]


class ProviderUnavailable(Error):
    """The provider cannot make a call at all: no API key, or the SDK is not installed."""

    def __init__(self, reason: str) -> None:
        super().__init__(ErrorClass.INVALID_REQUEST, RuntimeError(reason))
        self.reason = reason


class ProviderStopped(RuntimeError):
    """The model ended without a usable answer (refused, or cut off)."""

    def __init__(self, model: str, reason: str, category: str = "") -> None:
        detail = f"{model} stopped: {reason}"
        if category:
            detail = f"{detail} ({category})"
        super().__init__(detail)
        self.model = model
        self.reason = reason
        self.category = category


def claude_effort(thinking_budget: Optional[int]) -> Optional[str]:
    """The effort level a route's thinking budget asks for; None leaves the model's default."""
    if thinking_budget is None or thinking_budget < 0:
        return None
    return "low" if thinking_budget <= _LOW_EFFORT_MAX_BUDGET else "medium"


def message_usage(message: Any) -> tuple[int, int, int]:
    """(input, output without thinking, thinking) tokens of a finished message.

    The API counts thinking inside ``output_tokens`` and reports it again in
    ``output_tokens_details``; it is split out here so each token is priced once.
    """
    usage = getattr(message, "usage", None)
    if usage is None:
        return 0, 0, 0
    details = getattr(usage, "output_tokens_details", None)
    thinking = int(getattr(details, "thinking_tokens", 0) or 0)
    output = int(getattr(usage, "output_tokens", 0) or 0)
    return (
        int(getattr(usage, "input_tokens", 0) or 0),
        max(output - thinking, 0),
        thinking,
    )


def strip_json_fence(text: str) -> str:
    """The text without a wrapping ```json fence; anything else is returned as is."""
    body = text.strip()
    if not (body.startswith("```") and body.endswith("```") and len(body) >= 6):
        return text
    inner = body[3:-3]
    first, _, rest = inner.partition("\n")
    if rest and first.strip().isalnum():
        inner = rest
    return inner.strip()


class AnthropicChatProvider:
    """Stateless beyond its client. One provider per process is plenty: the
    client owns the connection pool.

    ``family`` (kielo_shared.llmroute) puts the provider under the AI-models
    control plane like GeminiSDKProvider: the model and thinking budget resolve
    through llmroute (the request's model / default_model and ``thinking_budget``
    are the fail-open default), calls are admitted under the family's budget and
    each one is rolled up as usage. The process must declare the provider with
    ``llmroute.allow_providers({PROVIDER_ANTHROPIC}, [family])``. A caller that
    already does this bookkeeping itself passes no family and reads usage from
    ``usage_sink(input, output, thinking)``. ``guarded=False`` skips the spend
    guard for a caller that admits every call itself (an eval harness with its
    own USD ceiling), so a call is not counted twice.
    """

    def __init__(
        self,
        api_key: str = "",
        *,
        client: Optional[Any] = None,
        default_model: str = "",
        family: str = "",
        thinking_budget: int = llmroute.THINKING_DEFAULT,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_retries: int = DEFAULT_MAX_RETRIES,
        usage_sink: Optional[UsageSink] = None,
        guarded: bool = True,
    ) -> None:
        self._api_key = api_key
        self._client = client
        self._default_model = default_model
        self._family = family
        self._thinking_budget = thinking_budget
        self._max_tokens = max_tokens
        self._timeout = timeout
        self._max_retries = max_retries
        self._usage_sink = usage_sink
        self._guarded = guarded

    @property
    def provider_id(self) -> str:
        return f"anthropic-messages:{self._default_model}"

    def _resolve_client(self) -> Any:
        if self._client is not None:
            return self._client
        if not self._api_key:
            raise ProviderUnavailable("Anthropic API key not configured")
        try:
            import anthropic  # type: ignore[import-not-found]
        except ImportError as exc:
            raise ProviderUnavailable(
                "the anthropic SDK is not installed (pip install kielo-shared[anthropic])"
            ) from exc
        self._client = anthropic.AsyncAnthropic(
            api_key=self._api_key,
            timeout=self._timeout,
            max_retries=self._max_retries,
        )
        return self._client

    def _route(self, request: Request) -> "llmroute.Route":
        default = request.model or self._default_model
        if not self._family:
            return llmroute.Route(default, self._thinking_budget)
        key = (request.metadata or {}).get("route_key")
        route = llmroute.resolve(
            self._family,
            default,
            self._thinking_budget,
            key=str(key) if key else None,
        )
        if route.provider and route.provider != llmroute.PROVIDER_ANTHROPIC:
            raise Error(
                ErrorClass.INVALID_REQUEST,
                RuntimeError(
                    f"family {self._family} routes to {route.provider}:{route.model}; "
                    "this provider only drives Claude"
                ),
            )
        return route

    def _kwargs(self, request: Request, route: "llmroute.Route") -> dict[str, Any]:
        if not route.model:
            raise Error(
                ErrorClass.INVALID_REQUEST,
                RuntimeError("no Anthropic model: the llm route supplies it"),
            )
        system = request.system_prompt
        if request.response_mime_type == "application/json":
            system = f"{system}\n\n{_JSON_ONLY}" if system else _JSON_ONLY
        kwargs: dict[str, Any] = {
            "model": route.model,
            "max_tokens": self._max_tokens,
            "messages": [{"role": "user", "content": request.prompt}],
        }
        if system:
            kwargs["system"] = system
        effort = claude_effort(route.thinking_budget)
        if effort:
            kwargs["output_config"] = {"effort": effort}
        return kwargs

    def _settle(
        self,
        route: "llmroute.Route",
        message: Any,
        started: float,
        task: str,
    ) -> str:
        """Book a finished message and return its text, or raise when it holds no usable answer."""
        text = "".join(
            str(getattr(block, "text", "") or "")
            for block in (getattr(message, "content", None) or [])
            if getattr(block, "type", "") == "text"
        )
        stop = getattr(message, "stop_reason", None)
        cause: Optional[ProviderStopped] = None
        error_class = ErrorClass.PROVIDER_ERROR
        outcome = llmroute.OUTCOME_OK
        if stop == _REFUSAL:
            details = getattr(message, "stop_details", None)
            category = str(getattr(details, "category", "") or "")
            cause = ProviderStopped(route.model, _REFUSAL, category)
            outcome = llmroute.OUTCOME_REFUSED
        elif stop in _CUT_OFF:
            cause = ProviderStopped(route.model, str(stop))
            outcome = llmroute.OUTCOME_INVALID_OUTPUT
        elif not text:
            error_class = ErrorClass.EMPTY_RESPONSE
            cause = ProviderStopped(route.model, "empty text")
            outcome = llmroute.OUTCOME_INVALID_OUTPUT
        self._record(route, message_usage(message), started, False, outcome, task)
        if cause is not None:
            raise Error(error_class, cause) from cause
        return text

    def _record(
        self,
        route: "llmroute.Route",
        tokens: tuple[int, int, int],
        started: float,
        failed: bool,
        outcome: str,
        task: str,
    ) -> None:
        try:
            tin, tout, think = tokens
            if self._usage_sink is not None and not failed:
                self._usage_sink(tin, tout, think)
            if not self._family:
                return
            usd = estimate_usd(route.model, tin, tout, think)
            if not failed:
                record_actual_usd(usd, family=self._family)
            llmroute.record_call(
                self._family,
                route.model,
                input_tokens=tin,
                output_tokens=tout,
                thinking_tokens=think,
                usd=usd,
                latency_ms=(time.perf_counter() - started) * 1000,
                error=failed,
                outcome=outcome,
                fallback=bool(route.requested),
                variant=route.variant,
                requested=route.requested or route.model,
                task=task or None,
            )
        except Exception:
            pass

    def _prepare(
        self, request: Request
    ) -> tuple[Any, "llmroute.Route", dict[str, Any]]:
        if not request.prompt:
            raise Error(ErrorClass.INVALID_REQUEST, RuntimeError("empty prompt"))
        client = self._resolve_client()
        route = self._route(request)
        kwargs = self._kwargs(request, route)
        if self._guarded:
            admit_paid_call(
                getattr(request, "task", ""),
                provider=self.provider_id,
                family=self._family,
            )
        return client, route, kwargs

    def _failed(
        self, exc: Exception, route: "llmroute.Route", started: float, task: str
    ) -> Error:
        self._record(route, (0, 0, 0), started, True, llmroute.OUTCOME_ERROR, task)
        return Error(_classify_anthropic_exception(exc), exc)

    async def generate(self, request: Request) -> Result:
        client, route, kwargs = self._prepare(request)
        started = time.perf_counter()
        try:
            message = await client.messages.create(**kwargs)
        except Error:
            raise
        except Exception as exc:
            raise self._failed(exc, route, started, request.task) from exc
        text = self._settle(route, message, started, request.task)
        if request.response_mime_type == "application/json":
            text = strip_json_fence(text)
        return Result(
            raw_text=text,
            provider=self.provider_id,
            latency_ms=int((time.perf_counter() - started) * 1000),
        )

    async def generate_stream(self, request: Request) -> AsyncIterator[str]:
        """Yield text deltas as the API produces them. A refusal or cut-off
        arrives after the text so far, as the same ``Error`` ``generate`` raises.
        A JSON answer is yielded as the model wrote it: strip a fence with
        ``strip_json_fence`` once the stream is joined.
        """
        client, route, kwargs = self._prepare(request)
        started = time.perf_counter()
        try:
            async with client.messages.stream(**kwargs) as stream:
                async for text in stream.text_stream:
                    if text:
                        yield str(text)
                message = await stream.get_final_message()
        except Error:
            raise
        except Exception as exc:
            raise self._failed(exc, route, started, request.task) from exc
        self._settle(route, message, started, request.task)


def _classify_anthropic_exception(exc: BaseException) -> ErrorClass:
    """Map an Anthropic SDK exception to a bounded ErrorClass. Matches the HTTP
    status when the exception carries one, else the class name and message, so
    SDK hierarchy changes do not move the label vocabulary."""
    name = type(exc).__name__.lower()
    msg = str(exc).lower()
    status = getattr(exc, "status_code", None)
    if "timeout" in name or "timeout" in msg or "deadline" in name:
        return ErrorClass.TIMEOUT
    if "connection" in name or "connect" in msg:
        return ErrorClass.CONNECTION
    if isinstance(status, int):
        if status == 429 or status >= 500:
            return ErrorClass.SERVER_ERROR
        if 400 <= status < 500:
            return ErrorClass.CLIENT_ERROR
    if "ratelimit" in name or "overloaded" in name or "internalserver" in name:
        return ErrorClass.SERVER_ERROR
    if "auth" in name or "permission" in name or "badrequest" in name:
        return ErrorClass.CLIENT_ERROR
    return ErrorClass.PROVIDER_ERROR
