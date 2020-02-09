﻿using GitHub.DistributedTask.WebApi;
using GitHub.Services.Common;
using GitHub.Services.WebApi;
using GitHub.Runner.Listener;
using GitHub.Runner.Listener.Configuration;
using Moq;
using System;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using Xunit;
using System.Threading;
using System.Reflection;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace GitHub.Runner.Common.Tests.Listener
{
    public sealed class MessageListenerL0
    {
        private RunnerSettings _settings;
        private Mock<IConfigurationManager> _config;
        private Mock<IRunnerServer> _runnerServer;
        private Mock<ICredentialManager> _credMgr;
        private Mock<IConfigurationStore> _store;

        public MessageListenerL0()
        {
            _settings = new RunnerSettings { AgentId = 1, AgentName = "myagent", PoolId = 123, PoolName = "default", ServerUrl = "http://myserver", WorkFolder = "_work" };
            _config = new Mock<IConfigurationManager>();
            _config.Setup(x => x.LoadSettings()).Returns(_settings);
            _runnerServer = new Mock<IRunnerServer>();
            _credMgr = new Mock<ICredentialManager>();
            _store = new Mock<IConfigurationStore>();
        }

        private TestHostContext CreateTestContext([CallerMemberName] String testName = "")
        {
            TestHostContext tc = new TestHostContext(this, testName);
            tc.SetSingleton<IConfigurationManager>(_config.Object);
            tc.SetSingleton<IRunnerServer>(_runnerServer.Object);
            tc.SetSingleton<ICredentialManager>(_credMgr.Object);
            tc.SetSingleton<IConfigurationStore>(_store.Object);
            return tc;
        }

        [Fact]
        [Trait("Level", "L0")]
        [Trait("Category", "Runner")]
        public async void CreatesSession()
        {
            using (TestHostContext tc = CreateTestContext())
            using (var tokenSource = new CancellationTokenSource())
            {
                Tracing trace = tc.GetTrace();

                // Arrange.
                var expectedSession = new TaskAgentSession();
                _runnerServer
                    .Setup(x => x.CreateAgentSessionAsync(
                        _settings.PoolId,
                        It.Is<TaskAgentSession>(y => y != null),
                        tokenSource.Token))
                    .Returns(Task.FromResult(expectedSession));

                _credMgr.Setup(x => x.LoadCredentials(true)).Returns(new VssCredentials());
                _store.Setup(x => x.GetCredentials()).Returns(new CredentialData() { Scheme = Constants.Configuration.OAuthAccessToken });
                _store.Setup(x => x.GetV2Credentials()).Returns(default(CredentialData));

                // Act.
                MessageListener listener = new MessageListener();
                listener.Initialize(tc);

                bool result = await listener.CreateSessionAsync(tokenSource.Token);
                trace.Info("result: {0}", result);

                // Assert.
                Assert.True(result);
                _runnerServer
                    .Verify(x => x.CreateAgentSessionAsync(
                        _settings.PoolId,
                        It.Is<TaskAgentSession>(y => y != null),
                        tokenSource.Token), Times.Once());
            }
        }

        [Fact]
        [Trait("Level", "L0")]
        [Trait("Category", "Runner")]
        public async void DeleteSession()
        {
            using (TestHostContext tc = CreateTestContext())
            using (var tokenSource = new CancellationTokenSource())
            {
                Tracing trace = tc.GetTrace();

                // Arrange.
                var expectedSession = new TaskAgentSession();
                PropertyInfo sessionIdProperty = expectedSession.GetType().GetProperty("SessionId", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public);
                Assert.NotNull(sessionIdProperty);
                sessionIdProperty.SetValue(expectedSession, Guid.NewGuid());

                _runnerServer
                    .Setup(x => x.CreateAgentSessionAsync(
                        _settings.PoolId,
                        It.Is<TaskAgentSession>(y => y != null),
                        tokenSource.Token))
                    .Returns(Task.FromResult(expectedSession));

                _credMgr.Setup(x => x.LoadCredentials(true)).Returns(new VssCredentials());
                _store.Setup(x => x.GetCredentials()).Returns(new CredentialData() { Scheme = Constants.Configuration.OAuthAccessToken });
                _store.Setup(x => x.GetV2Credentials()).Returns(default(CredentialData));

                // Act.
                MessageListener listener = new MessageListener();
                listener.Initialize(tc);

                bool result = await listener.CreateSessionAsync(tokenSource.Token);
                Assert.True(result);

                _runnerServer
                    .Setup(x => x.DeleteAgentSessionAsync(
                        _settings.PoolId, expectedSession.SessionId, It.IsAny<CancellationToken>()))
                    .Returns(Task.CompletedTask);
                await listener.DeleteSessionAsync();

                //Assert
                _runnerServer
                    .Verify(x => x.DeleteAgentSessionAsync(
                        _settings.PoolId, expectedSession.SessionId, It.IsAny<CancellationToken>()), Times.Once());
            }
        }

        [Fact]
        [Trait("Level", "L0")]
        [Trait("Category", "Runner")]
        public async void GetNextMessage()
        {
            using (TestHostContext tc = CreateTestContext())
            using (var tokenSource = new CancellationTokenSource())
            {
                Tracing trace = tc.GetTrace();

                // Arrange.
                var expectedSession = new TaskAgentSession();
                PropertyInfo sessionIdProperty = expectedSession.GetType().GetProperty("SessionId", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public);
                Assert.NotNull(sessionIdProperty);
                sessionIdProperty.SetValue(expectedSession, Guid.NewGuid());

                _runnerServer
                    .Setup(x => x.CreateAgentSessionAsync(
                        _settings.PoolId,
                        It.Is<TaskAgentSession>(y => y != null),
                        tokenSource.Token))
                    .Returns(Task.FromResult(expectedSession));

                _credMgr.Setup(x => x.LoadCredentials(true)).Returns(new VssCredentials());
                _store.Setup(x => x.GetCredentials()).Returns(new CredentialData() { Scheme = Constants.Configuration.OAuthAccessToken });
                _store.Setup(x => x.GetV2Credentials()).Returns(default(CredentialData));

                // Act.
                MessageListener listener = new MessageListener();
                listener.Initialize(tc);

                bool result = await listener.CreateSessionAsync(tokenSource.Token);
                Assert.True(result);

                var arMessages = new TaskAgentMessage[]
                {
                        new TaskAgentMessage
                        {
                            Body = "somebody1",
                            MessageId = 4234,
                            MessageType = JobRequestMessageTypes.PipelineAgentJobRequest
                        },
                        new TaskAgentMessage
                        {
                            Body = "somebody2",
                            MessageId = 4235,
                            MessageType = JobCancelMessage.MessageType
                        },
                        null,  //should be skipped by GetNextMessageAsync implementation
                        null,
                        new TaskAgentMessage
                        {
                            Body = "somebody3",
                            MessageId = 4236,
                            MessageType = JobRequestMessageTypes.PipelineAgentJobRequest
                        }
                };
                var messages = new Queue<TaskAgentMessage>(arMessages);

                _runnerServer
                    .Setup(x => x.GetAgentMessageAsync(
                        _settings.PoolId, expectedSession.SessionId, It.IsAny<long?>(), tokenSource.Token))
                    .Returns(async (Int32 poolId, Guid sessionId, Int64? lastMessageId, CancellationToken cancellationToken) =>
                    {
                        await Task.Yield();
                        return messages.Dequeue();
                    });
                TaskAgentMessage message1 = await listener.GetNextMessageAsync(tokenSource.Token);
                TaskAgentMessage message2 = await listener.GetNextMessageAsync(tokenSource.Token);
                TaskAgentMessage message3 = await listener.GetNextMessageAsync(tokenSource.Token);
                Assert.Equal(arMessages[0], message1);
                Assert.Equal(arMessages[1], message2);
                Assert.Equal(arMessages[4], message3);

                //Assert
                _runnerServer
                    .Verify(x => x.GetAgentMessageAsync(
                        _settings.PoolId, expectedSession.SessionId, It.IsAny<long?>(), tokenSource.Token), Times.Exactly(arMessages.Length));
            }
        }

        [Fact]
        [Trait("Level", "L0")]
        [Trait("Category", "Runner")]
        public async void CreateSessionWithV1Credential()
        {
            using (TestHostContext tc = CreateTestContext())
            using (var tokenSource = new CancellationTokenSource())
            {
                tc.Real100MSDelay = true;
                Tracing trace = tc.GetTrace();

                // Arrange.
                var expectedSession = new TaskAgentSession();
                _runnerServer
                    .Setup(x => x.CreateAgentSessionAsync(
                        _settings.PoolId,
                        It.Is<TaskAgentSession>(y => y != null),
                        tokenSource.Token))
                    .Returns(Task.FromResult(expectedSession));

                _credMgr.Setup(x => x.LoadCredentials(true)).Returns(new VssCredentials());

                var v1Cred = new CredentialData() { Scheme = Constants.Configuration.OAuth };
                v1Cred.Data["authorizationUrl"] = "https://s.server";
                v1Cred.Data["clientId"] = "d842fd7b-61b0-4a80-96b4-f2797c353897";

                _store.Setup(x => x.GetCredentials()).Returns(v1Cred);
                _store.Setup(x => x.GetV2Credentials()).Returns(default(CredentialData));

                // Act.
                MessageListener listener = new MessageListener();
                listener.Initialize(tc);

                bool result = await listener.CreateSessionAsync(tokenSource.Token);
                trace.Info("result: {0}", result);

                // Assert.
                Assert.True(result);
                _runnerServer
                    .Verify(x => x.CreateAgentSessionAsync(
                        _settings.PoolId,
                        It.Is<TaskAgentSession>(y => y != null),
                        tokenSource.Token), Times.Once());

                Assert.False(listener._useV2Credentials);
                Assert.True(listener._v1CredentialsExists);
                Assert.True(listener._needNewAuthorizationUrl);
                Assert.False(listener._authorizationUrlUpdated);
                Assert.False(listener._rollbackedV1Credentials);
                Assert.Null(listener._rollbackReattemptDelay);
                Assert.NotNull(listener._newAuthorizationUrlMigration);
            }
        }

        [Fact]
        [Trait("Level", "L0")]
        [Trait("Category", "Runner")]
        public async void CreateSessionWithV2Credential()
        {
            using (TestHostContext tc = CreateTestContext())
            using (var tokenSource = new CancellationTokenSource())
            {
                tc.Real100MSDelay = true;
                Tracing trace = tc.GetTrace();

                // Arrange.
                var expectedSession = new TaskAgentSession();
                _runnerServer
                    .Setup(x => x.CreateAgentSessionAsync(
                        _settings.PoolId,
                        It.Is<TaskAgentSession>(y => y != null),
                        tokenSource.Token))
                    .Returns(Task.FromResult(expectedSession));

                _credMgr.Setup(x => x.LoadCredentials(true)).Returns(new VssCredentials());

                var v1Cred = new CredentialData() { Scheme = Constants.Configuration.OAuth };
                v1Cred.Data["authorizationUrl"] = "https://s.server";
                v1Cred.Data["clientId"] = "d842fd7b-61b0-4a80-96b4-f2797c353897";

                var v2Cred = new CredentialData() { Scheme = Constants.Configuration.OAuth };
                v2Cred.Data["authorizationUrl"] = "https://t.server";
                v2Cred.Data["clientId"] = "d842fd7b-61b0-4a80-96b4-f2797c353897";

                _store.Setup(x => x.GetCredentials()).Returns(v1Cred);
                _store.Setup(x => x.GetV2Credentials()).Returns(v2Cred);

                // Act.
                MessageListener listener = new MessageListener();
                listener.Initialize(tc);

                bool result = await listener.CreateSessionAsync(tokenSource.Token);
                trace.Info("result: {0}", result);

                // Assert.
                Assert.True(result);
                _runnerServer
                    .Verify(x => x.CreateAgentSessionAsync(
                        _settings.PoolId,
                        It.Is<TaskAgentSession>(y => y != null),
                        tokenSource.Token), Times.Once());

                Assert.True(listener._useV2Credentials);
                Assert.True(listener._v1CredentialsExists);
                Assert.False(listener._needNewAuthorizationUrl);
                Assert.False(listener._authorizationUrlUpdated);
                Assert.False(listener._rollbackedV1Credentials);
                Assert.Null(listener._rollbackReattemptDelay);
                Assert.Null(listener._newAuthorizationUrlMigration);
            }
        }

        [Fact]
        [Trait("Level", "L0")]
        [Trait("Category", "Runner")]
        public async void CreateSessionWithHostedCredential()
        {
            using (TestHostContext tc = CreateTestContext())
            using (var tokenSource = new CancellationTokenSource())
            {
                tc.Real100MSDelay = true;
                Tracing trace = tc.GetTrace();

                // Arrange.
                var expectedSession = new TaskAgentSession();
                _runnerServer
                    .Setup(x => x.CreateAgentSessionAsync(
                        _settings.PoolId,
                        It.Is<TaskAgentSession>(y => y != null),
                        tokenSource.Token))
                    .Returns(Task.FromResult(expectedSession));

                _credMgr.Setup(x => x.LoadCredentials(true)).Returns(new VssCredentials());

                _store.Setup(x => x.GetCredentials()).Returns(new CredentialData() { Scheme = Constants.Configuration.OAuthAccessToken });
                _store.Setup(x => x.GetV2Credentials()).Returns(default(CredentialData));

                // Act.
                MessageListener listener = new MessageListener();
                listener.Initialize(tc);

                bool result = await listener.CreateSessionAsync(tokenSource.Token);
                trace.Info("result: {0}", result);

                // Assert.
                Assert.True(result);
                _runnerServer
                    .Verify(x => x.CreateAgentSessionAsync(
                        _settings.PoolId,
                        It.Is<TaskAgentSession>(y => y != null),
                        tokenSource.Token), Times.Once());

                Assert.False(listener._useV2Credentials);
                Assert.True(listener._v1CredentialsExists);
                Assert.False(listener._needNewAuthorizationUrl);
                Assert.False(listener._authorizationUrlUpdated);
                Assert.False(listener._rollbackedV1Credentials);
                Assert.Null(listener._rollbackReattemptDelay);
                Assert.Null(listener._newAuthorizationUrlMigration);
            }
        }

        [Fact]
        [Trait("Level", "L0")]
        [Trait("Category", "Runner")]
        public async void CreateSessionWithV2CredentialFallBackV1Succeed()
        {
            using (TestHostContext tc = CreateTestContext())
            using (var tokenSource = new CancellationTokenSource())
            {
                tc.Real100MSDelay = true;
                Tracing trace = tc.GetTrace();

                // Arrange.
                var expectedSession = new TaskAgentSession();
                _runnerServer
                    .Setup(x => x.CreateAgentSessionAsync(
                        123,
                        It.Is<TaskAgentSession>(y => y != null),
                        tokenSource.Token))
                    .Callback(() => { _settings.PoolId = 1234; })
                    .Throws(new TaskAgentPoolNotFoundException("L0 Pool not found"));

                _runnerServer
                    .Setup(x => x.CreateAgentSessionAsync(
                        1234,
                        It.Is<TaskAgentSession>(y => y != null),
                        tokenSource.Token))
                    .Returns(Task.FromResult(expectedSession));

                var v1VssCred = new VssCredentials();
                var v2VssCred = new VssCredentials();
                _credMgr.Setup(x => x.LoadCredentials(true)).Returns(v1VssCred);
                _credMgr.Setup(x => x.LoadCredentials(false)).Returns(v2VssCred);

                var v1Cred = new CredentialData() { Scheme = Constants.Configuration.OAuth };
                v1Cred.Data["authorizationUrl"] = "https://s.server";
                v1Cred.Data["clientId"] = "d842fd7b-61b0-4a80-96b4-f2797c353897";

                var v2Cred = new CredentialData() { Scheme = Constants.Configuration.OAuth };
                v2Cred.Data["authorizationUrl"] = "https://t.server";
                v2Cred.Data["clientId"] = "d842fd7b-61b0-4a80-96b4-f2797c353897";

                _store.Setup(x => x.GetCredentials()).Returns(v1Cred);
                _store.Setup(x => x.GetV2Credentials()).Returns(v2Cred);

                // Act.
                MessageListener listener = new MessageListener();
                listener.Initialize(tc);

                bool result = await listener.CreateSessionAsync(tokenSource.Token);
                trace.Info("result: {0}", result);

                // Assert.
                Assert.True(result);
                _runnerServer
                    .Verify(x => x.CreateAgentSessionAsync(
                        It.IsAny<int>(),
                        It.Is<TaskAgentSession>(y => y != null),
                        tokenSource.Token), Times.Exactly(2));
                _runnerServer
                    .Verify(x => x.ConnectAsync(
                        It.IsAny<Uri>(),
                        v1VssCred), Times.Once);
                _runnerServer
                    .Verify(x => x.ConnectAsync(
                        It.IsAny<Uri>(),
                        v2VssCred), Times.Once);

                Assert.False(listener._useV2Credentials);
                Assert.True(listener._v1CredentialsExists);
                Assert.False(listener._needNewAuthorizationUrl);
                Assert.False(listener._authorizationUrlUpdated);
                Assert.True(listener._rollbackedV1Credentials);
                Assert.NotNull(listener._rollbackReattemptDelay);
                Assert.Null(listener._newAuthorizationUrlMigration);
            }
        }

        [Fact]
        [Trait("Level", "L0")]
        [Trait("Category", "Runner")]
        public async void CreateSessionWithV2CredentialFallBackV1StillFailed()
        {
            using (TestHostContext tc = CreateTestContext())
            using (var tokenSource = new CancellationTokenSource())
            {
                tc.Real100MSDelay = true;
                Tracing trace = tc.GetTrace();

                // Arrange.
                var expectedSession = new TaskAgentSession();
                _runnerServer
                    .Setup(x => x.CreateAgentSessionAsync(
                        _settings.PoolId,
                        It.Is<TaskAgentSession>(y => y != null),
                        tokenSource.Token))
                    .Throws(new TaskAgentPoolNotFoundException("L0 Pool not found"));

                var v1VssCred = new VssCredentials();
                var v2VssCred = new VssCredentials();
                _credMgr.Setup(x => x.LoadCredentials(true)).Returns(v1VssCred);
                _credMgr.Setup(x => x.LoadCredentials(false)).Returns(v2VssCred);

                var v1Cred = new CredentialData() { Scheme = Constants.Configuration.OAuth };
                v1Cred.Data["authorizationUrl"] = "https://s.server";
                v1Cred.Data["clientId"] = "d842fd7b-61b0-4a80-96b4-f2797c353897";

                var v2Cred = new CredentialData() { Scheme = Constants.Configuration.OAuth };
                v2Cred.Data["authorizationUrl"] = "https://t.server";
                v2Cred.Data["clientId"] = "d842fd7b-61b0-4a80-96b4-f2797c353897";

                _store.Setup(x => x.GetCredentials()).Returns(v1Cred);
                _store.Setup(x => x.GetV2Credentials()).Returns(v2Cred);

                // Act.
                MessageListener listener = new MessageListener();
                listener.Initialize(tc);

                bool result = await listener.CreateSessionAsync(tokenSource.Token);
                trace.Info("result: {0}", result);

                // Assert.
                Assert.False(result);
                _runnerServer
                    .Verify(x => x.CreateAgentSessionAsync(
                        _settings.PoolId,
                        It.Is<TaskAgentSession>(y => y != null),
                        tokenSource.Token), Times.Exactly(2));
                _runnerServer
                    .Verify(x => x.ConnectAsync(
                        It.IsAny<Uri>(),
                        v1VssCred), Times.Once);
                _runnerServer
                    .Verify(x => x.ConnectAsync(
                        It.IsAny<Uri>(),
                        v2VssCred), Times.Once);

                Assert.False(listener._useV2Credentials);
                Assert.True(listener._v1CredentialsExists);
                Assert.False(listener._needNewAuthorizationUrl);
                Assert.False(listener._authorizationUrlUpdated);
                Assert.True(listener._rollbackedV1Credentials);
                Assert.NotNull(listener._rollbackReattemptDelay);
                Assert.Null(listener._newAuthorizationUrlMigration);
            }
        }

        [Fact]
        [Trait("Level", "L0")]
        [Trait("Category", "Runner")]
        public async void CreateSessionWithV1GetMessageWaitForMigtateToV2()
        {
            using (TestHostContext tc = CreateTestContext())
            using (var tokenSource = new CancellationTokenSource())
            {
                tc.Real100MSDelay = true;
                Tracing trace = tc.GetTrace();

                // Arrange.
                var expectedSession = new TaskAgentSession();
                _runnerServer
                    .Setup(x => x.CreateAgentSessionAsync(
                        _settings.PoolId,
                        It.Is<TaskAgentSession>(y => y != null),
                        tokenSource.Token))
                    .Returns(Task.FromResult(expectedSession));

                _runnerServer
                    .Setup(x => x.GetRunnerAuthUrlAsync(
                        _settings.PoolId,
                        _settings.AgentId))
                    .Returns(Task.FromResult(""));

                _credMgr.Setup(x => x.LoadCredentials(true)).Returns(new VssCredentials());

                var v1Cred = new CredentialData() { Scheme = Constants.Configuration.OAuth };
                v1Cred.Data["authorizationUrl"] = "https://s.server";
                v1Cred.Data["clientId"] = "d842fd7b-61b0-4a80-96b4-f2797c353897";

                _store.Setup(x => x.GetCredentials()).Returns(v1Cred);
                _store.Setup(x => x.GetV2Credentials()).Returns(default(CredentialData));

                // Act.
                MessageListener listener = new MessageListener();
                listener.Initialize(tc);

                bool result = await listener.CreateSessionAsync(tokenSource.Token);
                trace.Info("result: {0}", result);

                // Assert.
                Assert.True(result);
                _runnerServer
                    .Verify(x => x.CreateAgentSessionAsync(
                        _settings.PoolId,
                        It.Is<TaskAgentSession>(y => y != null),
                        tokenSource.Token), Times.Once());

                Assert.False(listener._useV2Credentials);
                Assert.True(listener._v1CredentialsExists);
                Assert.True(listener._needNewAuthorizationUrl);
                Assert.False(listener._authorizationUrlUpdated);
                Assert.False(listener._rollbackedV1Credentials);
                Assert.Null(listener._rollbackReattemptDelay);
                Assert.NotNull(listener._newAuthorizationUrlMigration);

                var arMessages = new TaskAgentMessage[]
                                {
                        new TaskAgentMessage
                        {
                            Body = "somebody1",
                            MessageId = 4234,
                            MessageType = JobRequestMessageTypes.PipelineAgentJobRequest
                        },
                        new TaskAgentMessage
                        {
                            Body = "somebody2",
                            MessageId = 4235,
                            MessageType = JobCancelMessage.MessageType
                        },
                        null,  //should be skipped by GetNextMessageAsync implementation
                        null,
                        new TaskAgentMessage
                        {
                            Body = "somebody3",
                            MessageId = 4236,
                            MessageType = JobRequestMessageTypes.PipelineAgentJobRequest
                        }
                                };
                var messages = new Queue<TaskAgentMessage>(arMessages);

                _runnerServer
                    .Setup(x => x.GetAgentMessageAsync(
                        _settings.PoolId, expectedSession.SessionId, It.IsAny<long?>(), tokenSource.Token))
                    .Returns(async (Int32 poolId, Guid sessionId, Int64? lastMessageId, CancellationToken cancellationToken) =>
                    {
                        await Task.Yield();
                        return messages.Dequeue();
                    });

                TaskAgentMessage message1 = await listener.GetNextMessageAsync(tokenSource.Token);
                await Task.Delay(100);
                TaskAgentMessage message2 = await listener.GetNextMessageAsync(tokenSource.Token);
                await Task.Delay(100);
                TaskAgentMessage message3 = await listener.GetNextMessageAsync(tokenSource.Token);
                await Task.Delay(100);
                Assert.Equal(arMessages[0], message1);
                Assert.Equal(arMessages[1], message2);
                Assert.Equal(arMessages[4], message3);

                //Assert
                _runnerServer
                    .Verify(x => x.GetAgentMessageAsync(
                        _settings.PoolId, expectedSession.SessionId, It.IsAny<long?>(), tokenSource.Token), Times.Exactly(arMessages.Length));

                _runnerServer
                    .Verify(x => x.GetRunnerAuthUrlAsync(_settings.PoolId, _settings.AgentId), Times.AtLeast(2));

                _runnerServer
                    .Verify(x => x.ConnectAsync(
                        It.IsAny<Uri>(),
                        It.IsAny<VssCredentials>()), Times.Once);

                var traceContent = File.ReadAllLines(tc.TraceFileName);
                Assert.DoesNotContain(traceContent, x => x.Contains("Try connect service with v2 OAuth endpoint."));

                Assert.False(listener._useV2Credentials);
                Assert.True(listener._v1CredentialsExists);
                Assert.True(listener._needNewAuthorizationUrl);
                Assert.False(listener._authorizationUrlUpdated);
                Assert.False(listener._rollbackedV1Credentials);
                Assert.Null(listener._rollbackReattemptDelay);
                Assert.NotNull(listener._newAuthorizationUrlMigration);
            }
        }

        [Fact]
        [Trait("Level", "L0")]
        [Trait("Category", "Runner")]
        public async void CreateSessionWithV1GetMessageMigtateToV2()
        {
            using (TestHostContext tc = CreateTestContext())
            using (var tokenSource = new CancellationTokenSource())
            {
                tc.Real100MSDelay = true;
                Tracing trace = tc.GetTrace();

                // Arrange.
                var expectedSession = new TaskAgentSession();
                _runnerServer
                    .Setup(x => x.CreateAgentSessionAsync(
                        _settings.PoolId,
                        It.Is<TaskAgentSession>(y => y != null),
                        tokenSource.Token))
                    .Returns(Task.FromResult(expectedSession));

                _runnerServer
                    .Setup(x => x.GetRunnerAuthUrlAsync(
                        _settings.PoolId,
                        _settings.AgentId))
                    .Returns(Task.FromResult("https://t.server"));

                _credMgr.Setup(x => x.LoadCredentials(true)).Returns(new VssCredentials());

                var v1Cred = new CredentialData() { Scheme = Constants.Configuration.OAuth };
                v1Cred.Data["authorizationUrl"] = "https://s.server";
                v1Cred.Data["clientId"] = "d842fd7b-61b0-4a80-96b4-f2797c353897";

                _store.Setup(x => x.GetCredentials()).Returns(v1Cred);
                _store.Setup(x => x.GetV2Credentials()).Returns(default(CredentialData));

                // Act.
                MessageListener listener = new MessageListener();
                listener.Initialize(tc);

                bool result = await listener.CreateSessionAsync(tokenSource.Token);
                trace.Info("result: {0}", result);

                // Assert.
                Assert.True(result);
                _runnerServer
                    .Verify(x => x.CreateAgentSessionAsync(
                        _settings.PoolId,
                        It.Is<TaskAgentSession>(y => y != null),
                        tokenSource.Token), Times.Once());

                Assert.False(listener._useV2Credentials);
                Assert.True(listener._v1CredentialsExists);
                Assert.True(listener._needNewAuthorizationUrl);
                Assert.False(listener._authorizationUrlUpdated);
                Assert.False(listener._rollbackedV1Credentials);
                Assert.Null(listener._rollbackReattemptDelay);
                Assert.NotNull(listener._newAuthorizationUrlMigration);

                var arMessages = new TaskAgentMessage[]
                                {
                        new TaskAgentMessage
                        {
                            Body = "somebody1",
                            MessageId = 4234,
                            MessageType = JobRequestMessageTypes.PipelineAgentJobRequest
                        },
                        new TaskAgentMessage
                        {
                            Body = "somebody2",
                            MessageId = 4235,
                            MessageType = JobCancelMessage.MessageType
                        },
                        null,  //should be skipped by GetNextMessageAsync implementation
                        null,
                        new TaskAgentMessage
                        {
                            Body = "somebody3",
                            MessageId = 4236,
                            MessageType = JobRequestMessageTypes.PipelineAgentJobRequest
                        }
                                };
                var messages = new Queue<TaskAgentMessage>(arMessages);

                _runnerServer
                    .Setup(x => x.GetAgentMessageAsync(
                        _settings.PoolId, expectedSession.SessionId, It.IsAny<long?>(), tokenSource.Token))
                    .Returns(async (Int32 poolId, Guid sessionId, Int64? lastMessageId, CancellationToken cancellationToken) =>
                    {
                        await Task.Yield();
                        return messages.Dequeue();
                    });

                var newRunnerServer = new Mock<IRunnerServer>();
                tc.EnqueueInstance<IRunnerServer>(newRunnerServer.Object);

                var keyManager = new Mock<IRSAKeyManager>();
                keyManager.Setup(x => x.GetKey()).Returns(new RSACryptoServiceProvider(2048));
                tc.SetSingleton(keyManager.Object);

                tc.SetSingleton<IJobDispatcher>(new Mock<IJobDispatcher>().Object);
                tc.SetSingleton<ISelfUpdater>(new Mock<ISelfUpdater>().Object);

                TaskAgentMessage message1 = await listener.GetNextMessageAsync(tokenSource.Token);
                await Task.Delay(100);
                TaskAgentMessage message2 = await listener.GetNextMessageAsync(tokenSource.Token);
                await Task.Delay(100);
                TaskAgentMessage message3 = await listener.GetNextMessageAsync(tokenSource.Token);
                await Task.Delay(100);
                Assert.Equal(arMessages[0], message1);
                Assert.Equal(arMessages[1], message2);
                Assert.Equal(arMessages[4], message3);

                //Assert
                _runnerServer
                    .Verify(x => x.GetAgentMessageAsync(
                        _settings.PoolId, expectedSession.SessionId, It.IsAny<long?>(), tokenSource.Token), Times.Exactly(arMessages.Length));

                _runnerServer
                    .Verify(x => x.GetRunnerAuthUrlAsync(_settings.PoolId, _settings.AgentId), Times.Once);

                _runnerServer
                    .Verify(x => x.ConnectAsync(
                        It.IsAny<Uri>(),
                        It.IsAny<VssCredentials>()), Times.Exactly(2));

                newRunnerServer
                    .Verify(x => x.ConnectAsync(
                            It.IsAny<Uri>(),
                            It.IsAny<VssCredentials>()), Times.Once);

                newRunnerServer
                    .Verify(x => x.GetAgentPoolsAsync(null, TaskAgentPoolType.Automation), Times.Once);

                var traceContent = File.ReadAllLines(tc.TraceFileName);
                Assert.Contains(traceContent, x => x.Contains("Try connect service with v2 OAuth endpoint."));

                Assert.True(listener._useV2Credentials);
                Assert.True(listener._v1CredentialsExists);
                Assert.False(listener._needNewAuthorizationUrl);
                Assert.True(listener._authorizationUrlUpdated);
                Assert.False(listener._rollbackedV1Credentials);
                Assert.Null(listener._rollbackReattemptDelay);
                Assert.Null(listener._newAuthorizationUrlMigration);
            }
        }

        [Fact]
        [Trait("Level", "L0")]
        [Trait("Category", "Runner")]
        public async void CreateSessionWithV2GetMessageNotMigrateAgain()
        {
            using (TestHostContext tc = CreateTestContext())
            using (var tokenSource = new CancellationTokenSource())
            {
                tc.Real100MSDelay = true;
                Tracing trace = tc.GetTrace();

                // Arrange.
                var expectedSession = new TaskAgentSession();
                _runnerServer
                    .Setup(x => x.CreateAgentSessionAsync(
                        _settings.PoolId,
                        It.Is<TaskAgentSession>(y => y != null),
                        tokenSource.Token))
                    .Returns(Task.FromResult(expectedSession));

                _runnerServer
                    .Setup(x => x.GetRunnerAuthUrlAsync(
                        _settings.PoolId,
                        _settings.AgentId))
                    .Returns(Task.FromResult("https://t.server"));

                _credMgr.Setup(x => x.LoadCredentials(true)).Returns(new VssCredentials());

                var v2Cred = new CredentialData() { Scheme = Constants.Configuration.OAuth };
                v2Cred.Data["authorizationUrl"] = "https://t.server";
                v2Cred.Data["clientId"] = "d842fd7b-61b0-4a80-96b4-f2797c353897";

                _store.Setup(x => x.GetCredentials()).Returns(v2Cred);
                _store.Setup(x => x.GetV2Credentials()).Returns(default(CredentialData));

                // Act.
                MessageListener listener = new MessageListener();
                listener.Initialize(tc);

                bool result = await listener.CreateSessionAsync(tokenSource.Token);
                trace.Info("result: {0}", result);

                // Assert.
                Assert.True(result);
                _runnerServer
                    .Verify(x => x.CreateAgentSessionAsync(
                        _settings.PoolId,
                        It.Is<TaskAgentSession>(y => y != null),
                        tokenSource.Token), Times.Once());

                Assert.False(listener._useV2Credentials);
                Assert.True(listener._v1CredentialsExists);
                Assert.True(listener._needNewAuthorizationUrl);
                Assert.False(listener._authorizationUrlUpdated);
                Assert.False(listener._rollbackedV1Credentials);
                Assert.Null(listener._rollbackReattemptDelay);
                Assert.NotNull(listener._newAuthorizationUrlMigration);

                var arMessages = new TaskAgentMessage[]
                                {
                        new TaskAgentMessage
                        {
                            Body = "somebody1",
                            MessageId = 4234,
                            MessageType = JobRequestMessageTypes.PipelineAgentJobRequest
                        },
                        new TaskAgentMessage
                        {
                            Body = "somebody2",
                            MessageId = 4235,
                            MessageType = JobCancelMessage.MessageType
                        },
                        null,  //should be skipped by GetNextMessageAsync implementation
                        null,
                        new TaskAgentMessage
                        {
                            Body = "somebody3",
                            MessageId = 4236,
                            MessageType = JobRequestMessageTypes.PipelineAgentJobRequest
                        }
                                };
                var messages = new Queue<TaskAgentMessage>(arMessages);

                _runnerServer
                    .Setup(x => x.GetAgentMessageAsync(
                        _settings.PoolId, expectedSession.SessionId, It.IsAny<long?>(), tokenSource.Token))
                    .Returns(async (Int32 poolId, Guid sessionId, Int64? lastMessageId, CancellationToken cancellationToken) =>
                    {
                        await Task.Yield();
                        return messages.Dequeue();
                    });

                var newRunnerServer = new Mock<IRunnerServer>();
                tc.EnqueueInstance<IRunnerServer>(newRunnerServer.Object);

                var keyManager = new Mock<IRSAKeyManager>();
                keyManager.Setup(x => x.GetKey()).Returns(new RSACryptoServiceProvider(2048));
                tc.SetSingleton(keyManager.Object);

                tc.SetSingleton<IJobDispatcher>(new Mock<IJobDispatcher>().Object);
                tc.SetSingleton<ISelfUpdater>(new Mock<ISelfUpdater>().Object);

                TaskAgentMessage message1 = await listener.GetNextMessageAsync(tokenSource.Token);
                await Task.Delay(100);
                TaskAgentMessage message2 = await listener.GetNextMessageAsync(tokenSource.Token);
                await Task.Delay(100);
                TaskAgentMessage message3 = await listener.GetNextMessageAsync(tokenSource.Token);
                await Task.Delay(100);
                Assert.Equal(arMessages[0], message1);
                Assert.Equal(arMessages[1], message2);
                Assert.Equal(arMessages[4], message3);

                //Assert
                _runnerServer
                    .Verify(x => x.GetAgentMessageAsync(
                        _settings.PoolId, expectedSession.SessionId, It.IsAny<long?>(), tokenSource.Token), Times.Exactly(arMessages.Length));

                _runnerServer
                    .Verify(x => x.GetRunnerAuthUrlAsync(_settings.PoolId, _settings.AgentId), Times.Once);

                _runnerServer
                    .Verify(x => x.ConnectAsync(
                        It.IsAny<Uri>(),
                        It.IsAny<VssCredentials>()), Times.Once);

                newRunnerServer
                    .Verify(x => x.ConnectAsync(
                            It.IsAny<Uri>(),
                            It.IsAny<VssCredentials>()), Times.Never);

                newRunnerServer
                    .Verify(x => x.GetAgentPoolsAsync(null, TaskAgentPoolType.Automation), Times.Never);

                var traceContent = File.ReadAllLines(tc.TraceFileName);
                Assert.Contains(traceContent, x => x.Contains("No needs to update authorization url"));

                Assert.False(listener._useV2Credentials);
                Assert.True(listener._v1CredentialsExists);
                Assert.True(listener._needNewAuthorizationUrl);
                Assert.False(listener._authorizationUrlUpdated);
                Assert.False(listener._rollbackedV1Credentials);
                Assert.Null(listener._rollbackReattemptDelay);
                Assert.NotNull(listener._newAuthorizationUrlMigration);
            }
        }

        [Fact]
        [Trait("Level", "L0")]
        [Trait("Category", "Runner")]
        public async void CreateSessionWithV1GetMessageMigrateToV2FallbackToV1()
        {
            using (TestHostContext tc = CreateTestContext())
            using (var tokenSource = new CancellationTokenSource())
            {
                tc.Real100MSDelay = true;
                Tracing trace = tc.GetTrace();

                // Arrange.
                var expectedSession = new TaskAgentSession();
                _runnerServer
                    .Setup(x => x.CreateAgentSessionAsync(
                        _settings.PoolId,
                        It.Is<TaskAgentSession>(y => y != null),
                        tokenSource.Token))
                    .Returns(Task.FromResult(expectedSession));

                var v1VssCred = new VssCredentials();
                var v2VssCred = new VssCredentials();
                _credMgr.Setup(x => x.LoadCredentials(true)).Returns(v1VssCred);
                _credMgr.Setup(x => x.LoadCredentials(false)).Returns(v2VssCred);

                var v1Cred = new CredentialData() { Scheme = Constants.Configuration.OAuth };
                v1Cred.Data["authorizationUrl"] = "https://s.server";
                v1Cred.Data["clientId"] = "d842fd7b-61b0-4a80-96b4-f2797c353897";

                var v2Cred = new CredentialData() { Scheme = Constants.Configuration.OAuth };
                v2Cred.Data["authorizationUrl"] = "https://t.server";
                v2Cred.Data["clientId"] = "d842fd7b-61b0-4a80-96b4-f2797c353897";

                _store.Setup(x => x.GetCredentials()).Returns(v1Cred);
                _store.Setup(x => x.GetV2Credentials()).Returns(v2Cred);

                // Act.
                MessageListener listener = new MessageListener();
                listener.Initialize(tc);

                bool result = await listener.CreateSessionAsync(tokenSource.Token);
                trace.Info("result: {0}", result);

                // Assert.
                Assert.True(result);
                _runnerServer
                    .Verify(x => x.CreateAgentSessionAsync(
                        _settings.PoolId,
                        It.Is<TaskAgentSession>(y => y != null),
                        tokenSource.Token), Times.Once());

                Assert.True(listener._useV2Credentials);
                Assert.True(listener._v1CredentialsExists);
                Assert.False(listener._needNewAuthorizationUrl);
                Assert.False(listener._authorizationUrlUpdated);
                Assert.False(listener._rollbackedV1Credentials);
                Assert.Null(listener._rollbackReattemptDelay);
                Assert.Null(listener._newAuthorizationUrlMigration);

                var arMessages = new TaskAgentMessage[]
                                {
                        new TaskAgentMessage
                        {
                            Body = "somebody1",
                            MessageId = 4234,
                            MessageType = JobRequestMessageTypes.PipelineAgentJobRequest
                        },
                        new TaskAgentMessage
                        {
                            Body = "somebody2",
                            MessageId = 4235,
                            MessageType = JobCancelMessage.MessageType
                        },
                        null,  //should be skipped by GetNextMessageAsync implementation
                        null,
                        new TaskAgentMessage
                        {
                            Body = "somebody3",
                            MessageId = 4236,
                            MessageType = JobRequestMessageTypes.PipelineAgentJobRequest
                        }
                                };
                var messages = new Queue<TaskAgentMessage>(arMessages);

                var counter = 0;
                _runnerServer
                    .Setup(x => x.GetAgentMessageAsync(
                        _settings.PoolId, expectedSession.SessionId, It.IsAny<long?>(), tokenSource.Token))
                    .Returns(async (Int32 poolId, Guid sessionId, Int64? lastMessageId, CancellationToken cancellationToken) =>
                    {
                        await Task.Yield();
                        counter++;

                        if (counter == 2)
                        {
                            throw new TaskAgentNotFoundException("L0 runner not found");
                        }

                        if (counter == 3)
                        {
                            Assert.True(listener._rollbackedV1Credentials);
                            Assert.NotNull(listener._rollbackReattemptDelay);
                        }

                        return messages.Dequeue();
                    });

                var newRunnerServer = new Mock<IRunnerServer>();
                tc.EnqueueInstance<IRunnerServer>(newRunnerServer.Object);

                var keyManager = new Mock<IRSAKeyManager>();
                keyManager.Setup(x => x.GetKey()).Returns(new RSACryptoServiceProvider(2048));
                tc.SetSingleton(keyManager.Object);

                tc.SetSingleton<IJobDispatcher>(new Mock<IJobDispatcher>().Object);
                tc.SetSingleton<ISelfUpdater>(new Mock<ISelfUpdater>().Object);

                TaskAgentMessage message1 = await listener.GetNextMessageAsync(tokenSource.Token);
                await Task.Delay(100);
                TaskAgentMessage message2 = await listener.GetNextMessageAsync(tokenSource.Token);
                await Task.Delay(10);
                TaskAgentMessage message3 = await listener.GetNextMessageAsync(tokenSource.Token);
                Assert.Equal(arMessages[0], message1);
                Assert.Equal(arMessages[1], message2);
                Assert.Equal(arMessages[4], message3);

                //Assert
                _runnerServer
                    .Verify(x => x.GetAgentMessageAsync(
                        _settings.PoolId, expectedSession.SessionId, It.IsAny<long?>(), tokenSource.Token), Times.Exactly(arMessages.Length + 1));

                _runnerServer
                    .Verify(x => x.GetRunnerAuthUrlAsync(_settings.PoolId, _settings.AgentId), Times.Never);

                _runnerServer
                    .Verify(x => x.ConnectAsync(
                        It.IsAny<Uri>(),
                        It.IsAny<VssCredentials>()), Times.Exactly(2));

                newRunnerServer
                    .Verify(x => x.ConnectAsync(
                            It.IsAny<Uri>(),
                            It.IsAny<VssCredentials>()), Times.Never);

                newRunnerServer
                    .Verify(x => x.GetAgentPoolsAsync(null, TaskAgentPoolType.Automation), Times.Never);

                var traceContent = File.ReadAllLines(tc.TraceFileName);
                Assert.Contains(traceContent, x => x.Contains("Fallback to v1 credentials and try again."));

                Assert.False(listener._useV2Credentials);
                Assert.True(listener._v1CredentialsExists);
                Assert.False(listener._needNewAuthorizationUrl);
                Assert.False(listener._authorizationUrlUpdated);
                Assert.True(listener._rollbackedV1Credentials);
                Assert.NotNull(listener._rollbackReattemptDelay);
                Assert.Null(listener._newAuthorizationUrlMigration);
            }
        }

        [Fact]
        [Trait("Level", "L0")]
        [Trait("Category", "Runner")]
        public async void CreateSessionWithV1GetMessageMigrateToV2FallbackToV1ReattemptV2()
        {
            using (TestHostContext tc = CreateTestContext())
            using (var tokenSource = new CancellationTokenSource())
            {
                tc.Real100MSDelay = true;
                Tracing trace = tc.GetTrace();

                // Arrange.
                var expectedSession = new TaskAgentSession();
                _runnerServer
                    .Setup(x => x.CreateAgentSessionAsync(
                        _settings.PoolId,
                        It.Is<TaskAgentSession>(y => y != null),
                        tokenSource.Token))
                    .Returns(Task.FromResult(expectedSession));

                var v1VssCred = new VssCredentials();
                var v2VssCred = new VssCredentials();
                _credMgr.Setup(x => x.LoadCredentials(true)).Returns(v1VssCred);
                _credMgr.Setup(x => x.LoadCredentials(false)).Returns(v2VssCred);

                var v1Cred = new CredentialData() { Scheme = Constants.Configuration.OAuth };
                v1Cred.Data["authorizationUrl"] = "https://s.server";
                v1Cred.Data["clientId"] = "d842fd7b-61b0-4a80-96b4-f2797c353897";

                var v2Cred = new CredentialData() { Scheme = Constants.Configuration.OAuth };
                v2Cred.Data["authorizationUrl"] = "https://t.server";
                v2Cred.Data["clientId"] = "d842fd7b-61b0-4a80-96b4-f2797c353897";

                _store.Setup(x => x.GetCredentials()).Returns(v1Cred);
                _store.Setup(x => x.GetV2Credentials()).Returns(v2Cred);

                // Act.
                MessageListener listener = new MessageListener();
                listener.Initialize(tc);

                bool result = await listener.CreateSessionAsync(tokenSource.Token);
                trace.Info("result: {0}", result);

                // Assert.
                Assert.True(result);
                _runnerServer
                    .Verify(x => x.CreateAgentSessionAsync(
                        _settings.PoolId,
                        It.Is<TaskAgentSession>(y => y != null),
                        tokenSource.Token), Times.Once());

                Assert.True(listener._useV2Credentials);
                Assert.True(listener._v1CredentialsExists);
                Assert.False(listener._needNewAuthorizationUrl);
                Assert.False(listener._authorizationUrlUpdated);
                Assert.False(listener._rollbackedV1Credentials);
                Assert.Null(listener._rollbackReattemptDelay);
                Assert.Null(listener._newAuthorizationUrlMigration);

                var arMessages = new TaskAgentMessage[]
                                {
                        new TaskAgentMessage
                        {
                            Body = "somebody1",
                            MessageId = 4234,
                            MessageType = JobRequestMessageTypes.PipelineAgentJobRequest
                        },
                        new TaskAgentMessage
                        {
                            Body = "somebody2",
                            MessageId = 4235,
                            MessageType = JobCancelMessage.MessageType
                        },
                        null,  //should be skipped by GetNextMessageAsync implementation
                        null,
                        new TaskAgentMessage
                        {
                            Body = "somebody3",
                            MessageId = 4236,
                            MessageType = JobRequestMessageTypes.PipelineAgentJobRequest
                        }
                                };
                var messages = new Queue<TaskAgentMessage>(arMessages);

                var counter = 0;
                _runnerServer
                    .Setup(x => x.GetAgentMessageAsync(
                        _settings.PoolId, expectedSession.SessionId, It.IsAny<long?>(), tokenSource.Token))
                    .Returns(async (Int32 poolId, Guid sessionId, Int64? lastMessageId, CancellationToken cancellationToken) =>
                    {
                        await Task.Yield();
                        counter++;

                        if (counter == 2)
                        {
                            throw new TaskAgentNotFoundException("L0 runner not found");
                        }

                        if (counter == 3)
                        {
                            Assert.True(listener._rollbackedV1Credentials);
                            Assert.NotNull(listener._rollbackReattemptDelay);
                        }

                        return messages.Dequeue();
                    });

                var newRunnerServer = new Mock<IRunnerServer>();
                tc.EnqueueInstance<IRunnerServer>(newRunnerServer.Object);

                var keyManager = new Mock<IRSAKeyManager>();
                keyManager.Setup(x => x.GetKey()).Returns(new RSACryptoServiceProvider(2048));
                tc.SetSingleton(keyManager.Object);

                tc.SetSingleton<IJobDispatcher>(new Mock<IJobDispatcher>().Object);
                tc.SetSingleton<ISelfUpdater>(new Mock<ISelfUpdater>().Object);

                TaskAgentMessage message1 = await listener.GetNextMessageAsync(tokenSource.Token);
                await Task.Delay(100);
                TaskAgentMessage message2 = await listener.GetNextMessageAsync(tokenSource.Token);
                await Task.Delay(200);
                TaskAgentMessage message3 = await listener.GetNextMessageAsync(tokenSource.Token);
                Assert.Equal(arMessages[0], message1);
                Assert.Equal(arMessages[1], message2);
                Assert.Equal(arMessages[4], message3);

                //Assert
                _runnerServer
                    .Verify(x => x.GetAgentMessageAsync(
                        _settings.PoolId, expectedSession.SessionId, It.IsAny<long?>(), tokenSource.Token), Times.Exactly(arMessages.Length + 1));

                _runnerServer
                    .Verify(x => x.GetRunnerAuthUrlAsync(_settings.PoolId, _settings.AgentId), Times.Never);

                _runnerServer
                    .Verify(x => x.ConnectAsync(
                        It.IsAny<Uri>(),
                        It.IsAny<VssCredentials>()), Times.Exactly(3));

                newRunnerServer
                    .Verify(x => x.ConnectAsync(
                            It.IsAny<Uri>(),
                            It.IsAny<VssCredentials>()), Times.Never);

                newRunnerServer
                    .Verify(x => x.GetAgentPoolsAsync(null, TaskAgentPoolType.Automation), Times.Never);

                var traceContent = File.ReadAllLines(tc.TraceFileName);
                Assert.Contains(traceContent, x => x.Contains("Fallback to v1 credentials and try again."));
                Assert.Contains(traceContent, x => x.Contains("Re-attempt to use v2 credential"));

                Assert.True(listener._useV2Credentials);
                Assert.True(listener._v1CredentialsExists);
                Assert.False(listener._needNewAuthorizationUrl);
                Assert.False(listener._authorizationUrlUpdated);
                Assert.False(listener._rollbackedV1Credentials);
                Assert.Null(listener._rollbackReattemptDelay);
                Assert.Null(listener._newAuthorizationUrlMigration);
            }
        }
    }
}
