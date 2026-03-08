using Antrapol.IdP.Crypto.Domain.Enums;
using Antrapol.IdP.SharedKernel.Events;

namespace Antrapol.IdP.Crypto.Domain.Events;

public sealed record KeyGeneratedEvent(Guid KeyId, string Label, KeyAlgorithm Algorithm, KeyStorageType StorageType) : DomainEvent;

public sealed record KeyDisabledEvent(Guid KeyId, string Label) : DomainEvent;

public sealed record KeyEnabledEvent(Guid KeyId, string Label) : DomainEvent;

public sealed record KeyCompromisedEvent(Guid KeyId, string Label) : DomainEvent;

public sealed record KeyDestroyedEvent(Guid KeyId, string Label) : DomainEvent;

public sealed record SignatureCreatedEvent(Guid KeyId, string DataHash) : DomainEvent;

public sealed record EncapsulationPerformedEvent(Guid KeyId) : DomainEvent;

public sealed record DecapsulationPerformedEvent(Guid KeyId) : DomainEvent;
