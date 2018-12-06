﻿using System;
using System.IO;
using System.IO.Pipes;
using System.Threading;
using CoreHook.IPC.Handlers;
using CoreHook.IPC.Messages;
using CoreHook.IPC.Platform;
using CoreHook.IPC.Transport;

namespace CoreHook.IPC.NamedPipes
{
    public class NamedPipeServer : INamedPipeServer
    {
        public IConnection Connection { get; private set; }
        public IMessageHandler MessageHandler { get; private set; }

        private const int MaxPipeNameLength = 250;
     
        private readonly Action<ITransportChannel> _handleTransportConnection;

        private readonly string _pipeName;
        private readonly IPipePlatform _platform;

        private bool _connectionStopped;
        private NamedPipeServerStream _listeningPipe;

        private NamedPipeServer(string pipeName, IPipePlatform platform, Action<ITransportChannel> handleTransportConnection)
        {
            _pipeName = pipeName;
            _platform = platform;
            _handleTransportConnection = handleTransportConnection;
            _connectionStopped = false;
        }

        public static INamedPipeServer StartNewServer(string pipeName, IPipePlatform platform, Action<IMessage, ITransportChannel> handleRequest)
        {
            if (pipeName.Length > MaxPipeNameLength)
            {
                throw new PipeMessageLengthException(pipeName, MaxPipeNameLength);
            }

            var pipeServer = new NamedPipeServer(pipeName, platform, connection => HandleTransportConnection(connection, handleRequest));
            pipeServer.OpenListeningPipe();
            return pipeServer;
        }

        public static INamedPipeServer StartNewServer(string pipeName, IPipePlatform platform, Action<ITransportChannel> handleRequest)
        {
            if (pipeName.Length > MaxPipeNameLength)
            {
                throw new PipeMessageLengthException(pipeName, MaxPipeNameLength);
            }

            var pipeServer = new NamedPipeServer(pipeName, platform, handleRequest);
            pipeServer.OpenListeningPipe();
            return pipeServer;
        }

        private static void HandleTransportConnection(ITransportChannel channel, Action<IMessage, ITransportChannel> handleRequest)
        {
            var connection = channel.Connection;

            while (connection.IsConnected)
            {
                var message = channel.MessageHandler.Read();
                if (message == null || !connection.IsConnected)
                {
                    break;
                }
                handleRequest(message, channel);
            }
        }

        public void OpenListeningPipe()
        {
            try
            {
                if (_listeningPipe != null)
                {
                    throw new InvalidOperationException("There is already a pipe listening for a connection");
                }
                _listeningPipe = _platform.CreatePipeByName(_pipeName);
                _listeningPipe.BeginWaitForConnection(OnNewConnection, _listeningPipe);
            }
            catch (Exception e)
            {
                LogError("OpenListeningPipe: unhandled exception", e);
            }
        }

        private void OnNewConnection(IAsyncResult ar)
        {
            // Check if we should be accepting any new connections.
            if (_connectionStopped)
            {
                return;
            }

            _listeningPipe = null;
            var connectionBroken = false;
            if (!(ar.AsyncState is NamedPipeServerStream pipe))
            {
                return;
            }

            try
            {
                try
                {
                    pipe.EndWaitForConnection(ar);
                }
                catch (IOException e)
                {
                    connectionBroken = true;
                    if (!_connectionStopped)
                    {
                        LogError($"OnNewConnection: IOException for pipe: {_pipeName}", e);
                    }
                }
                catch (ObjectDisposedException)
                {
                    if (!_connectionStopped)
                    {
                        throw;
                    }
                }
                catch (Exception e)
                {
                    LogError("OnNewConnection: unhandled exception", e);
                }
                if (!_connectionStopped && !connectionBroken)
                {
                    try
                    {
                        Connection = new PipeConnection(pipe, () => _connectionStopped);
                        MessageHandler = new MessageHandler(Connection);
                        _handleTransportConnection?.Invoke(this);
                    }
                    catch (Exception e)
                    {
                        LogError("Unhandled exception during server initialization", e);
                    }
                }
            }
            finally
            {
                pipe.Dispose();
            }
        }

        private static void LogError(string message, Exception e)
        {
            Console.WriteLine(message);
            Console.WriteLine(e);
        }

        public void Dispose()
        {
            _connectionStopped = true;

            NamedPipeServerStream pipe = Interlocked.Exchange(ref _listeningPipe, null);
            pipe?.Dispose();
        }
    }
}
