// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Collections.Generic;

namespace ArcForges.Contracts.LocalRpc.Notes;

// --- Enums ---

public enum NotesSearchScope
{
    CurrentDocument,
    Notebook,
    Workspace,
    DocumentSet,
}

public enum NotesSearchSort
{
    Relevance,
    Modified,
    Created,
    Title,
}

public enum DocumentSearchMatchKind
{
    Title,
    FullText,
    Tag,
    Property,
    AttachmentName,
    AttachmentText,
}

public enum TagMatchMode
{
    Exact,
    Descendants,
}

public enum PropertyOperator
{
    Eq,
    Neq,
    Gt,
    Gte,
    Lt,
    Lte,
    Contains,
    StartsWith,
    IsEmpty,
    IsNotEmpty,
}

public enum DocumentReadMode
{
    Full,
    HeaderOnly,
}

public enum ArtifactImportMode
{
    Embed,
    CopyContent,
    Link,
}

public enum NotesReviewMode
{
    Auto,
    Require,
    SkipAllowed,
}

public enum PropertyChangeOperation
{
    Set,
    Clear,
}

public enum DocumentRelationKind
{
    Reference,
    Related,
    Parent,
    Child,
}

public enum ArtifactNavigationMode
{
    Default,
    Document,
    Block,
}

public enum NotesImportSourceKind
{
    MarkdownFile,
    MarkdownDirectory,
    PlainText,
    Html,
    ObsidianVault,
    NotionExport,
}

public enum NotesExportFormat
{
    Native,
    Markdown,
    Html,
    Pdf,
    Docx,
    PlainText,
}

public enum ExternalAttachmentPolicy
{
    Ask,
    Copy,
    Link,
}

public enum ExistingOutputPolicy
{
    Replace,
    Rename,
    Cancel,
}

// --- Supporting DTOs ---

public sealed partial record NotesSearchFilterDto
{
    public IReadOnlyList<Guid>? NotebookIds { get; init; }
    public IReadOnlyList<Guid>? TagIds { get; init; }
    public bool IncludeTrashed { get; init; }
}

public sealed partial record DocumentSearchHitDto
{
    public required ResourceRef DocumentRef { get; init; }
    public required string Title { get; init; }
    public string? Snippet { get; init; }
    public required DocumentSearchMatchKind MatchKind { get; init; }
    public required IReadOnlyList<TypedAnchorDto> Anchors { get; init; }
    public required string Score { get; init; }
    public required DateTimeOffset ModifiedAtUtc { get; init; }
    public required long IndexedRevision { get; init; }
    public required bool IsStale { get; init; }
}

public sealed partial record TypedPropertyValueDto
{
    public required string TypeName { get; init; }
    public string? StringValue { get; init; }
    public double? NumberValue { get; init; }
    public bool? BooleanValue { get; init; }
    public DateTimeOffset? DateTimeValue { get; init; }
    public IReadOnlyList<string>? ArrayValue { get; init; }
}

public sealed partial record DocumentSummaryDto
{
    public required ResourceRef DocumentRef { get; init; }
    public required Guid NotebookId { get; init; }
    public Guid? FolderId { get; init; }
    public required string Title { get; init; }
    public required DateTimeOffset CreatedAtUtc { get; init; }
    public required DateTimeOffset ModifiedAtUtc { get; init; }
    public int BlockCount { get; init; }
    public required IReadOnlyList<Guid> TagIds { get; init; }
    public DateTimeOffset? TrashedAtUtc { get; init; }
    public required ResourceAvailability Availability { get; init; }
}

public sealed partial record PropertyAssignmentDto
{
    public required Guid DefinitionId { get; init; }
    public required string Name { get; init; }
    public required TypedPropertyValueDto Value { get; init; }
}

public sealed partial record DocumentLinkDto
{
    public required Guid TargetDocumentId { get; init; }
    public required DocumentRelationKind Relation { get; init; }
    public string? Anchor { get; init; }
}

public sealed partial record AttachmentSummaryDto
{
    public required Guid AttachmentId { get; init; }
    public required string FileName { get; init; }
    public required string ContentType { get; init; }
    public long SizeBytes { get; init; }
    public required ResourceRef ResourceRef { get; init; }
}

public sealed partial record DocumentMetadataDto
{
    public required DocumentSummaryDto Summary { get; init; }
    public required IReadOnlyList<PropertyAssignmentDto> Properties { get; init; }
    public required IReadOnlyList<DocumentLinkDto> Links { get; init; }
    public required IReadOnlyList<AttachmentSummaryDto> Attachments { get; init; }
    public required ArtifactProvenance Provenance { get; init; }
    public bool KnowledgeEligibility { get; init; }
}

public sealed partial record BlockSnapshotDto
{
    public required Guid BlockId { get; init; }
    public Guid? ParentBlockId { get; init; }
    public required string BlockType { get; init; }
    public required string ContentJson { get; init; }
    public string? PropertyJson { get; init; }
    public required long Revision { get; init; }
}

public sealed partial record DocumentSnapshotDto
{
    public required DocumentMetadataDto Metadata { get; init; }
    public required IReadOnlyList<Guid> RootBlockIds { get; init; }
    public required IReadOnlyList<BlockSnapshotDto> Blocks { get; init; }
}

public sealed partial record BlockReadSelectorDto
{
    public IReadOnlyList<Guid>? BlockIds { get; init; }
    public string? StartAnchor { get; init; }
    public string? EndAnchor { get; init; }
    public int? MaxBlocks { get; init; }
}

public sealed partial record BlockReadResultDto
{
    public required ResourceRef DocumentRef { get; init; }
    public required IReadOnlyList<BlockSnapshotDto> Blocks { get; init; }
    public bool HasMore { get; init; }
    public string? NextAnchor { get; init; }
}

public sealed partial record NotesSelectionRefDto
{
    public required ResourceRef DocumentRef { get; init; }
    public required long Revision { get; init; }
    public required string StartAnchor { get; init; }
    public required string EndAnchor { get; init; }
    public required IReadOnlyList<Guid> SelectedBlockIds { get; init; }
}

public sealed partial record SelectionSnapshotDto
{
    public required NotesSelectionRefDto Selection { get; init; }
    public required IReadOnlyList<BlockSnapshotDto> Blocks { get; init; }
    public string? PlainText { get; init; }
}

public sealed partial record BlockCreateDto
{
    public Guid? ClientBlockId { get; init; }
    public required string BlockType { get; init; }
    public required string ContentJson { get; init; }
    public string? PropertyJson { get; init; }
    public IReadOnlyList<BlockCreateDto>? Children { get; init; }
}

public sealed partial record BlockReplacementDto
{
    public required Guid BlockId { get; init; }
    public required IReadOnlyList<BlockCreateDto> NewBlocks { get; init; }
}

public sealed partial record PropertyChangeDto
{
    public required Guid DefinitionId { get; init; }
    public required PropertyChangeOperation Operation { get; init; }
    public TypedPropertyValueDto? Value { get; init; }
}

public sealed partial record DocumentMutationResultDto
{
    public required ResourceRef DocumentRef { get; init; }
    public required IReadOnlyList<Guid> ChangedBlockIds { get; init; }
    public ResourceRef? CheckpointRef { get; init; }
    public bool ReviewRequired { get; init; }
}

public sealed partial record OpenArtifactResultDto
{
    public required ResourceRef OpenedResourceRef { get; init; }
    public string? ResolvedAnchor { get; init; }
    public required Guid WindowId { get; init; }
}

public sealed partial record NotesImportOptionsDto
{
    public bool PreserveTimestamps { get; init; }
    public bool ImportAttachments { get; init; }
    public string? TagPrefix { get; init; }
}

public sealed partial record ImportAcceptedDto
{
    public required ProductActivityRefDto Activity { get; init; }
    public ArtifactRef? ReportArtifact { get; init; }
}

public sealed partial record ExportAcceptedDto
{
    public required ProductActivityRefDto Activity { get; init; }
}

public sealed partial record PermanentDeleteResultDto
{
    public required Guid DeletedDocumentId { get; init; }
    public required long DeletedRevision { get; init; }
    public required Guid TombstoneId { get; init; }
}

public sealed partial record NotesContextSnapshotDto
{
    public ResourceRef? CurrentDocumentRef { get; init; }
    public NotesSelectionRefDto? CurrentSelection { get; init; }
    public ResourceRef? CurrentBlockRef { get; init; }
    public ResourceRef? CurrentNotebookRef { get; init; }
    public required IReadOnlyList<ResourceRef> OpenDocumentRefs { get; init; }
    public required IReadOnlyList<ResourceRef> CurrentSearchResultRefs { get; init; }
}

// --- 23 Request / Response Pairs ---

// 1. SearchDocuments
public sealed partial record SearchDocumentsRequest
{
    public required Guid RequestId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public string? Cursor { get; init; }
    public int Limit { get; init; } = 50;
    public required string Text { get; init; }
    public required NotesSearchScope Scope { get; init; }
    public Guid? ScopeId { get; init; }
    public IReadOnlyList<Guid>? DocumentIds { get; init; }
    public NotesSearchFilterDto? Filters { get; init; }
    public NotesSearchSort Sort { get; init; } = NotesSearchSort.Relevance;
}

public sealed partial record SearchDocumentsResponse
{
    public required IReadOnlyList<DocumentSearchHitDto> Items { get; init; }
    public string? NextCursor { get; init; }
    public long SnapshotRevision { get; init; }
}

// 2. FindByTag
public sealed partial record FindByTagRequest
{
    public required Guid RequestId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public string? Cursor { get; init; }
    public int Limit { get; init; } = 50;
    public required Guid TagId { get; init; }
    public Guid? NotebookId { get; init; }
    public TagMatchMode Match { get; init; } = TagMatchMode.Exact;
    public bool IncludeTrashed { get; init; }
}

public sealed partial record FindByTagResponse
{
    public required IReadOnlyList<DocumentSummaryDto> Items { get; init; }
    public string? NextCursor { get; init; }
    public long SnapshotRevision { get; init; }
}

// 3. FindByProperty
public sealed partial record FindByPropertyRequest
{
    public required Guid RequestId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public string? Cursor { get; init; }
    public int Limit { get; init; } = 50;
    public required Guid PropertyDefinitionId { get; init; }
    public required PropertyOperator Operator { get; init; }
    public TypedPropertyValueDto? Value { get; init; }
    public Guid? NotebookId { get; init; }
}

public sealed partial record FindByPropertyResponse
{
    public required IReadOnlyList<DocumentSummaryDto> Items { get; init; }
    public string? NextCursor { get; init; }
    public long SnapshotRevision { get; init; }
}

// 4. GetDocumentSummary
public sealed partial record GetDocumentSummaryRequest
{
    public required Guid RequestId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef DocumentRef { get; init; }
    public long? Revision { get; init; }
}

public sealed partial record GetDocumentSummaryResponse
{
    public required DocumentSummaryDto Value { get; init; }
    public long SnapshotRevision { get; init; }
}

// 5. GetDocumentMetadata
public sealed partial record GetDocumentMetadataRequest
{
    public required Guid RequestId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef DocumentRef { get; init; }
    public long? Revision { get; init; }
}

public sealed partial record GetDocumentMetadataResponse
{
    public required DocumentMetadataDto Value { get; init; }
    public long SnapshotRevision { get; init; }
}

// 6. ReadDocument
public sealed partial record ReadDocumentRequest
{
    public required Guid RequestId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef DocumentRef { get; init; }
    public DocumentReadMode Mode { get; init; } = DocumentReadMode.Full;
    public long? Revision { get; init; }
    public long? ExpectedMinRevision { get; init; }
}

public sealed partial record ReadDocumentResponse
{
    public required DocumentSnapshotDto Value { get; init; }
    public long SnapshotRevision { get; init; }
}

// 7. ReadBlocks
public sealed partial record ReadBlocksRequest
{
    public required Guid RequestId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef DocumentRef { get; init; }
    public long? Revision { get; init; }
    public required BlockReadSelectorDto Selector { get; init; }
}

public sealed partial record ReadBlocksResponse
{
    public required BlockReadResultDto Value { get; init; }
    public long SnapshotRevision { get; init; }
}

// 8. ReadSelection
public sealed partial record ReadSelectionRequest
{
    public required Guid RequestId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required NotesSelectionRefDto Selection { get; init; }
    public int IncludeContextBlocks { get; init; }
}

public sealed partial record ReadSelectionResponse
{
    public required SelectionSnapshotDto Value { get; init; }
    public long SnapshotRevision { get; init; }
}

// 9. CreateDocument
public sealed partial record CreateDocumentRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public ResourceRef? TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required Guid NotebookId { get; init; }
    public Guid? FolderId { get; init; }
    public string? Title { get; init; }
    public Guid? TemplateId { get; init; }
    public IReadOnlyList<BlockCreateDto>? InitialBlocks { get; init; }
    public required ArtifactProvenance Provenance { get; init; }
}

public sealed partial record CreateDocumentResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public DocumentMutationResultDto? Value { get; init; }
}

// 10. CreateFromArtifact
public sealed partial record CreateFromArtifactRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public ResourceRef? TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required ArtifactRef ArtifactRef { get; init; }
    public required Guid TargetNotebookId { get; init; }
    public Guid? TargetFolderId { get; init; }
    public string? Title { get; init; }
    public ArtifactImportMode ImportMode { get; init; } = ArtifactImportMode.Embed;
    public required long ExpectedArtifactRevision { get; init; }
}

public sealed partial record CreateFromArtifactResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public DocumentMutationResultDto? Value { get; init; }
}

// 11. InsertBlocks
public sealed partial record InsertBlocksRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required ResourceRef DocumentRef { get; init; }
    public Guid? ParentBlockId { get; init; }
    public Guid? BeforeBlockId { get; init; }
    public required IReadOnlyList<BlockCreateDto> Blocks { get; init; }
    public required NotesReviewMode ReviewMode { get; init; }
}

public sealed partial record InsertBlocksResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public DocumentMutationResultDto? Value { get; init; }
}

// 12. ReplaceBlocks
public sealed partial record ReplaceBlocksRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required ResourceRef DocumentRef { get; init; }
    public required IReadOnlyList<BlockReplacementDto> Replacements { get; init; }
    public required NotesReviewMode ReviewMode { get; init; }
}

public sealed partial record ReplaceBlocksResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public DocumentMutationResultDto? Value { get; init; }
}

// 13. AppendBlocks
public sealed partial record AppendBlocksRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required ResourceRef DocumentRef { get; init; }
    public required IReadOnlyList<BlockCreateDto> Blocks { get; init; }
    public required NotesReviewMode ReviewMode { get; init; }
}

public sealed partial record AppendBlocksResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public DocumentMutationResultDto? Value { get; init; }
}

// 14. UpdateProperties
public sealed partial record UpdatePropertiesRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required ResourceRef DocumentRef { get; init; }
    public required IReadOnlyList<PropertyChangeDto> Changes { get; init; }
}

public sealed partial record UpdatePropertiesResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public DocumentMutationResultDto? Value { get; init; }
}

// 15. AddTags
public sealed partial record AddTagsRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required ResourceRef DocumentRef { get; init; }
    public required IReadOnlyList<Guid> TagIds { get; init; }
}

public sealed partial record AddTagsResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public DocumentMutationResultDto? Value { get; init; }
}

// 16. MoveDocument
public sealed partial record MoveDocumentRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required ResourceRef DocumentRef { get; init; }
    public required Guid TargetNotebookId { get; init; }
    public Guid? TargetFolderId { get; init; }
    public Guid? BeforeDocumentId { get; init; }
}

public sealed partial record MoveDocumentResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public DocumentMutationResultDto? Value { get; init; }
}

// 17. LinkDocuments
public sealed partial record LinkDocumentsRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required ResourceRef SourceDocumentRef { get; init; }
    public required ResourceRef TargetDocumentRef { get; init; }
    public required DocumentRelationKind RelationKind { get; init; }
    public bool Bidirectional { get; init; }
}

public sealed partial record LinkDocumentsResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public DocumentMutationResultDto? Value { get; init; }
}

// 18. OpenArtifact
public sealed partial record OpenArtifactRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public ResourceRef? TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required ArtifactRef ArtifactRef { get; init; }
    public ArtifactNavigationMode Navigation { get; init; } = ArtifactNavigationMode.Default;
    public TypedAnchorDto? Anchor { get; init; }
    public bool ActivateWindow { get; init; }
}

public sealed partial record OpenArtifactResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public OpenArtifactResultDto? Value { get; init; }
}

// 19. Import
public sealed partial record ImportRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public ResourceRef? TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required ResourceRef Source { get; init; }
    public required NotesImportSourceKind SourceKind { get; init; }
    public required Guid TargetNotebookId { get; init; }
    public Guid? TargetFolderId { get; init; }
    public NotesImportOptionsDto? Options { get; init; }
}

public sealed partial record ImportResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public ImportAcceptedDto? Value { get; init; }
}

// 20. Export
public sealed partial record ExportRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public ResourceRef? TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required IReadOnlyList<ResourceRef> DocumentRefs { get; init; }
    public required NotesExportFormat Format { get; init; }
    public required LocalOutputTargetDto Target { get; init; }
    public ExternalAttachmentPolicy ExternalAttachmentPolicy { get; init; } = ExternalAttachmentPolicy.Ask;
    public ExistingOutputPolicy ExistingOutputPolicy { get; init; } = ExistingOutputPolicy.Replace;
}

public sealed partial record ExportResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public ExportAcceptedDto? Value { get; init; }
}

// 21. TrashDocument
public sealed partial record TrashDocumentRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required ResourceRef DocumentRef { get; init; }
    public string? Reason { get; init; }
}

public sealed partial record TrashDocumentResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public DocumentMutationResultDto? Value { get; init; }
}

// 22. DeleteDocumentPermanent
public sealed partial record DeleteDocumentPermanentRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required ResourceRef DocumentRef { get; init; }
    public required string ConfirmationToken { get; init; }
    public required string Reason { get; init; }
}

public sealed partial record DeleteDocumentPermanentResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public PermanentDeleteResultDto? Value { get; init; }
}

// 23. GetContext
public sealed partial record GetContextRequest
{
    public required Guid RequestId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required IReadOnlyList<string> Include { get; init; }
    public int MaxRefs { get; init; } = 50;
}

public sealed partial record GetContextResponse
{
    public required NotesContextSnapshotDto Value { get; init; }
    public long SnapshotRevision { get; init; }
}
