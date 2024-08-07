﻿using CoreHook.IPC.Messages;
using CoreHook.IPC.Platform;

using Microsoft.Extensions.Logging;

using System;
using System.IO;
using System.IO.Pipes;
using System.Threading.Tasks;

namespace CoreHook.IPC.NamedPipes;

/// <summary>
/// Creates a pipe server and allows custom handling of messages from clients.
/// </summary>
public class NamedPipeServer : NamedPipeBase
{
    private readonly Action<INamedPipe, CustomMessage> _handleMessage;

    private readonly IPipePlatform _platform;

    private bool _connectionStopped;

    /// <summary>
    /// Initialize a new pipe server.
    /// </summary>
    /// <param name="pipeName">The name of the pipe server.</param>
    /// <param name="platform">Method for initializing a new pipe-based server.</param>
    /// <param name="handleMessage">Event handler called when receiving a new message from a client.</param>
    /// <param name="logger"></param>
    /// <returns>An instance of the new pipe server.</returns>
    public NamedPipeServer(string pipeName, IPipePlatform platform, Action<INamedPipe, CustomMessage> handleMessage, ILogger logger)
    {
        _context = $"{pipeName} (server)"; 
        _handleMessage = handleMessage;
        _pipeName = pipeName;
        _platform = platform;
        _logger = logger;

        Connect();
    }

    private async Task HandleMessages()
    {
        var pipeStream = (NamedPipeServerStream)Stream!;

        while (!_connectionStopped & pipeStream is not null)
        {
            try
            {
                _logger.LogInformation("{context}: waiting for connection...", _context);

                await pipeStream.WaitForConnectionAsync();

                _logger.LogInformation("{context}: new client connected.", _context);

                while (pipeStream.IsConnected)
                {
                    var message = await Read();

                    // Only process the message if it has not been sent by the current thread, as both the client and server can write/read messages.
                    if (message is not null && message.SenderId != _namedPipeId)
                    {
                        _logger.LogDebug("{context}: message {id} will be handled by {pipeId}", _context, message.MessageId, this._namedPipeId);
                        _handleMessage?.Invoke(this, message);
                    }
                }
            }
            catch (IOException e) when ((uint)e.HResult is 0x80131620 or 0x8007006D /* Broken pipe */)
            {
                // If the connection is stopped (i.e. we don't need to listen anymore - and don't care about it), just skip
                if (!_connectionStopped)
                {
                    _logger.LogInformation("{context}: current client was disconnected.", _context);
                    // Disconnecting "cleanly" as the pipe was broken without proper disconnection
                    pipeStream.Disconnect();
                }
            }
        }
    }

    /// <inheritdoc />
    public override async void Connect()
    {
        if (Stream is not null)
        {
            throw new InvalidOperationException($"{_pipeName} (server): Pipe server already started");
        }

        Stream = _platform.CreatePipeByName(_pipeName);
        
        await Task.Run(() => HandleMessages());
    }

    /// <inheritdoc />
    public new void Dispose()
    {
        _logger.LogInformation("{pipeName} (server): Disposing.", _pipeName);

        _connectionStopped = true;

        base.Dispose();
    }
}
