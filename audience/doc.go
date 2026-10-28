// Package audience compiles an admin-built audience definition (ADR-016 section 2) into SQL over the
// user-service schema. It is pure: no database access, every value travels as a placeholder argument.
//
// A definition is {"version":1,"all":[{"field":..,"op":..,"value":..}]}. Every condition must hold; an
// empty list means every real learner. Every query implicitly requires users.learner_class_v1.class = 'real'.
//
// Fields (see Catalog for the admin-facing labels):
//
//	platform           in               ["ios","android","web"]
//	support_language   in               ["en","vi"]
//	learning_language  in               ["fi","sv"]
//	signed_up          within_days | before_days            N
//	last_active        within_days | not_within_days        N
//	plus               is               never_paid | paid_before | paid_active | promo_active | any_active | none
//	plus_ends          within_days                          N
//	paywall_viewed     within_days                          N (saw the paywall and has not bought since)
//	used_feature       within_days                          {"feature":"juka|ktv|reader|lessons","days":N}
//	email_marketing    is               true
//	push_enabled       is               true
//	campaign           clicked_within_days | shown_within_days   {"campaign_id":"<uuid>","days":N}
//
// Consumers number their own placeholders: Members, Count and Member take the first placeholder number to
// use and return the arguments for exactly those placeholders.
package audience
