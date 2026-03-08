namespace Antrapol.IdP.SharedKernel.Entities;

/// <summary>
/// Base class for all entities with a UUID primary key.
/// </summary>
public abstract class Entity : IEquatable<Entity>
{
    public Guid Id { get; protected set; }

    protected Entity()
    {
    }

    protected Entity(Guid id)
    {
        Id = id;
    }

    public bool Equals(Entity? other)
    {
        if (other is null) return false;
        if (ReferenceEquals(this, other)) return true;
        return Id == other.Id;
    }

    public override bool Equals(object? obj)
    {
        if (obj is null) return false;
        if (ReferenceEquals(this, obj)) return true;
        if (obj.GetType() != GetType()) return false;
        return Equals((Entity)obj);
    }

    public override int GetHashCode() => Id.GetHashCode();

    public static bool operator ==(Entity? left, Entity? right) => Equals(left, right);
    public static bool operator !=(Entity? left, Entity? right) => !Equals(left, right);
}

/// <summary>
/// Base class for auditable entities that track creation and modification metadata.
/// </summary>
public abstract class AuditableEntity : Entity
{
    public DateTimeOffset CreatedAt { get; protected set; }
    public Guid? CreatedBy { get; protected set; }
    public DateTimeOffset? UpdatedAt { get; protected set; }
    public Guid? UpdatedBy { get; protected set; }
    public DateTimeOffset? DeletedAt { get; protected set; }
    public Guid? DeletedBy { get; protected set; }
    public int Version { get; protected set; } = 1;

    public bool IsDeleted => DeletedAt.HasValue;

    protected AuditableEntity()
    {
        CreatedAt = DateTimeOffset.UtcNow;
    }

    protected AuditableEntity(Guid id) : base(id)
    {
        CreatedAt = DateTimeOffset.UtcNow;
    }

    public void SetCreated(Guid? userId)
    {
        CreatedAt = DateTimeOffset.UtcNow;
        CreatedBy = userId;
    }

    public void SetUpdated(Guid? userId)
    {
        UpdatedAt = DateTimeOffset.UtcNow;
        UpdatedBy = userId;
        Version++;
    }

    public void SetDeleted(Guid? userId)
    {
        DeletedAt = DateTimeOffset.UtcNow;
        DeletedBy = userId;
    }
}
