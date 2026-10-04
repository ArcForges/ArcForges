// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Assistant.Abstractions;

/// <summary>Explicit immutable dependencies for exactly one live application composition.</summary>
public sealed class AssistantHostServices
{
    private int _creationStarted;
    private int _created;

    public AssistantHostServices(AssistantHostIdentity owner, IHostContext context, IHostActions actions,
        IHostResources resources, IHostNavigation navigation, IHostLifecycle lifecycle,
        IHostPlatformServices platform, IAssistantStoreScope store, IAssistantSessionFactory sessionFactory)
    {
        ArgumentNullException.ThrowIfNull(owner);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(actions);
        ArgumentNullException.ThrowIfNull(resources);
        ArgumentNullException.ThrowIfNull(navigation);
        ArgumentNullException.ThrowIfNull(lifecycle);
        ArgumentNullException.ThrowIfNull(platform);
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(sessionFactory);

        Owner = owner;
        Context = context;
        Actions = actions;
        Resources = resources;
        Navigation = navigation;
        Lifecycle = lifecycle;
        Platform = platform;
        Store = store;
        SessionFactory = sessionFactory;

        RequireOwner(context.Owner, nameof(context));
        RequireOwner(actions.Owner, nameof(actions));
        RequireOwner(resources.Owner, nameof(resources));
        RequireOwner(navigation.Owner, nameof(navigation));
        RequireOwner(lifecycle.Owner, nameof(lifecycle));
        RequireOwner(platform.Owner, nameof(platform));
        RequireChildOwner(platform.Dispatcher, "platform.Dispatcher");
        RequireChildOwner(platform.SecureStorage, "platform.SecureStorage");
        RequireChildOwner(platform.FilePicker, "platform.FilePicker");
        RequireChildOwner(platform.Clipboard, "platform.Clipboard");
        RequireChildOwner(platform.Environment, "platform.Environment");
        RequireOwner(sessionFactory.Owner, nameof(sessionFactory));
        if (store.Partition.Installation != owner.Installation)
        {
            throw new ArgumentException("The store partition belongs to a different product installation.", nameof(store));
        }
    }

    public AssistantHostIdentity Owner { get; }
    public IHostContext Context { get; }
    public IHostActions Actions { get; }
    public IHostResources Resources { get; }
    public IHostNavigation Navigation { get; }
    public IHostLifecycle Lifecycle { get; }
    public IHostPlatformServices Platform { get; }
    public IAssistantStoreScope Store { get; }
    public IAssistantSessionFactory SessionFactory { get; }

    internal void ValidateFor(AssistantHostOptions options)
    {
        if (options.Identity != Owner)
        {
            throw new ArgumentException("Host services cannot be reused by another product, installation, instance or epoch.", nameof(options));
        }

        if (Store.Partition != options.InitialStorePartition)
        {
            throw new ArgumentException("The store scope does not match the selected profile partition.", nameof(options));
        }
    }

    internal bool TryBeginCreation()
    {
        if (Volatile.Read(ref _created) != 0)
        {
            throw new InvalidOperationException("One application composition creates one session; windows reuse that session.");
        }

        return Interlocked.CompareExchange(ref _creationStarted, 1, 0) == 0;
    }

    internal void CompleteCreation()
    {
        Volatile.Write(ref _created, 1);
        if (Actions is AssistantActionRegistry registry)
        {
            registry.Seal();
        }
    }

    internal void CancelCreation() => Volatile.Write(ref _creationStarted, 0);

    private void RequireOwner(AssistantHostIdentity actual, string parameter)
    {
        if (actual != Owner)
        {
            throw new ArgumentException("Every injected host port must belong to the same application instance.", parameter);
        }
    }

    private void RequireChildOwner(IAssistantHostPort? port, string parameter)
    {
        if (port is null)
        {
            throw new ArgumentException("Every platform service sub-port must be supplied.", parameter);
        }

        RequireOwner(port.Owner, parameter);
    }
}

/// <summary>Validated entry point for an AOT-safe, explicit host composition.</summary>
public static class AssistantHost
{
    public static IAssistantSession Create(AssistantHostOptions options, AssistantHostServices services)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(services);
        services.ValidateFor(options);
        if (!services.TryBeginCreation())
        {
            throw new InvalidOperationException("Host composition is already being created.");
        }

        try
        {
            IAssistantSession session = services.SessionFactory.Create(options, services)
                ?? throw new InvalidOperationException("The explicit session factory returned no session.");
            if (session.Identity != options.Identity || !ReferenceEquals(session.Options, options) ||
                !ReferenceEquals(session.Services, services) || session.CurrentProfile != options.InitialProfile)
            {
                throw new InvalidOperationException("The session factory returned a session for a different host or profile.");
            }

            services.CompleteCreation();
            return session;
        }
        catch
        {
            services.CancelCreation();
            throw;
        }
    }
}
