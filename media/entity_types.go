package media

type EntityType string

const (
	EntityTypeGeneric          EntityType = ""
	EntityTypeUserAvatar       EntityType = "UserAvatar"
	EntityTypeArticleThumbnail EntityType = "ArticleThumbnail"
	EntityTypeArticleContent   EntityType = "ArticleContentMedia"
	EntityTypeKieloTVVideo     EntityType = "KieloTVVideo"
	EntityTypeKieloTVThumbnail EntityType = "KieloTVThumbnail"
	EntityTypeKieloTVCarousel  EntityType = "KieloTVCarouselImage"
	EntityTypeKieloTVAudio     EntityType = "KieloTVAudio"
	EntityTypeBaseWordAudio    EntityType = "BaseWordAudio"
	EntityTypeParagraphAudio   EntityType = "ParagraphAudio"
	EntityTypeConvoTranscript  EntityType = "ConvoSessionTranscript"
	EntityTypeConvoReview      EntityType = "ConvoSessionReview"
)

var ValidEntityTypes = []EntityType{
	EntityTypeUserAvatar,
	EntityTypeArticleThumbnail,
	EntityTypeArticleContent,
	EntityTypeKieloTVVideo,
	EntityTypeKieloTVThumbnail,
	EntityTypeKieloTVCarousel,
	EntityTypeKieloTVAudio,
	EntityTypeBaseWordAudio,
	EntityTypeParagraphAudio,
	EntityTypeConvoTranscript,
	EntityTypeConvoReview,
}

func IsValidEntityType(value string) bool {
	for _, entityType := range ValidEntityTypes {
		if string(entityType) == value {
			return true
		}
	}
	return false
}
