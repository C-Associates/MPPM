namespace MPPM.Cryptography.Channels;

using System;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// Represents a secure encrypted channel for communicating between relevant
/// peers. While P2P may necessitate that a party forward channel traffic to
/// another peer to support communication, it is expected that the method which
/// secures communications reveals nothing about the data being communicated
/// except to an intended recipient.
/// </summary>
public interface IChannel<T>
{
    /// <summary>
    /// Sends a message asynchronously over the channel.
    /// </summary>
    /// <param name="message">The message to send.</param>
    /// <param name="cancellationToken">
    /// A cancellation token that can be used by other objects or threads to
    /// receive notice of cancellation.
    /// </param>
    Task SendAsync(T message, CancellationToken cancellationToken);

    /// <summary>
    /// Sends a message over the channel.
    /// </summary>
    /// <param name="message">The message to send.</param>
    void Send(T message);

    /// <summary>
    /// OnReceiveAsync is raised when a message is received, handled
    /// asynchronously.
    /// </summary>
    event Func<T, CancellationToken, Task> OnReceiveAsync;

    /// <summary>
    /// OnReceive is raised when a message is received.
    /// </summary>
    event Action<T> OnReceive;
}
