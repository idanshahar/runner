using System;
using System.Threading.Tasks;
using GitHub.Runner.Common;
using GitHub.Runner.Common.Util;
using GitHub.Runner.Sdk;
using GitHub.Services.Common;
using GitHub.Services.OAuth;
using GitHub.Services.WebApi;

namespace GitHub.Runner.Listener.Configuration
{
    public class OAuthCredential : CredentialProvider
    {
        public OAuthCredential()
            : base(Constants.Configuration.OAuth)
        {
        }

        public override void EnsureCredential(
            IHostContext context,
            CommandSettings command,
            String serverUrl)
        {
            // Nothing to verify here
        }

        public override VssCredentials GetVssCredentials(IHostContext context)
        {
            var clientId = this.CredentialData.Data.GetValueOrDefault("clientId", null);
            var authorizationUrl = this.CredentialData.Data.GetValueOrDefault("authorizationUrl", null);

            // For back compat with .credential file that doesn't has 'oauthEndpointUrl' section
            var oauthEndpointUrl = this.CredentialData.Data.GetValueOrDefault("oauthEndpointUrl", authorizationUrl);

            ArgUtil.NotNullOrEmpty(clientId, nameof(clientId));
            ArgUtil.NotNullOrEmpty(authorizationUrl, nameof(authorizationUrl));

            // We expect the key to be in the machine store at this point. Configuration should have set all of
            // this up correctly so we can use the key to generate access tokens.
            var keyManager = context.GetService<IRSAKeyManager>();
            var signingCredentials = VssSigningCredentials.Create(() => keyManager.GetKey());
            var clientCredential = new VssOAuthJwtBearerClientCredential(clientId, authorizationUrl, signingCredentials);
            var agentCredential = new VssOAuthCredential(new Uri(oauthEndpointUrl, UriKind.Absolute), VssOAuthGrant.ClientCredentials, clientCredential);

            // Construct a credentials cache with a single OAuth credential for communication. The windows credential
            // is explicitly set to null to ensure we never do that negotiation.
            var oauthCredential = new VssCredentials(agentCredential, CredentialPromptType.DoNotPrompt);

            Uri authUrl = new Uri(authorizationUrl);
            if (authUrl.Host.StartsWith("vssps.", StringComparison.OrdinalIgnoreCase))
            {
                // Migrate auth url in .credentials from SPS to Token
                // Task.Run(async () => await MigrateOAuthEndpointUrl(context, clientId, authorizationUrl, oauthEndpointUrl, signingCredentials, oauthCredential));
            }

            return oauthCredential;
        }

        private async Task MigrateOAuthEndpointUrl(IHostContext context, string clientId, string authorizationUrl, string oauthEndpointUrl, VssSigningCredentials signingCredentials, VssCredentials oauthCredential)
        {
            var trace = context.GetTrace("AuthUrlMigration");
            try
            {
                var runnerSettings = context.GetService<IConfigurationStore>().GetSettings();
                var locationServer = context.GetService<ILocationServer>();
                await locationServer.ConnectAsync(new VssConnection(new Uri(runnerSettings.ServerUrl), oauthCredential));
                var connectionData = await locationServer.GetConnectionDataAsync();

                UriBuilder v2AuthorizationUrl = new UriBuilder(authorizationUrl);
                v2AuthorizationUrl.Host = v2AuthorizationUrl.Host.Replace("vssps.", "vstoken.");
                v2AuthorizationUrl.Path = v2AuthorizationUrl.Path.Substring(v2AuthorizationUrl.Path.IndexOf("_apis/"));
                v2AuthorizationUrl.Path = v2AuthorizationUrl.Path.TrimEnd('/') + $"/{connectionData.InstanceId.ToString("D")}";
                trace.Info($"V2 Authorization Url: {v2AuthorizationUrl.Uri.AbsoluteUri}");

                UriBuilder configServerUrl = new UriBuilder(runnerSettings.ServerUrl);
                UriBuilder v2OauthEndpointUrlBuilder = new UriBuilder(v2AuthorizationUrl.Uri);
                if (!connectionData.DeploymentType.HasFlag(DeploymentFlags.Hosted) && Uri.Compare(configServerUrl.Uri, v2OauthEndpointUrlBuilder.Uri, UriComponents.SchemeAndServer, UriFormat.Unescaped, StringComparison.OrdinalIgnoreCase) != 0)
                {
                    v2OauthEndpointUrlBuilder.Scheme = configServerUrl.Scheme;
                    v2OauthEndpointUrlBuilder.Host = configServerUrl.Host;
                    v2OauthEndpointUrlBuilder.Port = configServerUrl.Port;
                    trace.Info($"V2 OAuth endpoint Url: {v2OauthEndpointUrlBuilder.Uri.AbsoluteUri}");
                }

                var v2ClientCredential = new VssOAuthJwtBearerClientCredential(clientId, v2AuthorizationUrl.Uri.AbsoluteUri, signingCredentials);
                var v2RunnerCredential = new VssOAuthCredential(new Uri(v2OauthEndpointUrlBuilder.Uri.AbsoluteUri, UriKind.Absolute), VssOAuthGrant.ClientCredentials, v2ClientCredential);

                trace.Info("Try connect service with v2 OAuth endpoint.");
                var runnerServer = context.GetService<IRunnerServer>();
                await runnerServer.ConnectAsync(new Uri(runnerSettings.ServerUrl), v2RunnerCredential);
                var runners = await runnerServer.GetAgentsAsync(runnerSettings.PoolId);
                trace.Info($"Successfully connected service and retrived {runners.Count} runners.");

                var credDataV2 = new CredentialData
                {
                    Scheme = Constants.Configuration.OAuth,
                    Data =
                        {
                            { "clientId", clientId },
                            { "authorizationUrl", v2AuthorizationUrl.Uri.AbsoluteUri },
                            { "oauthEndpointUrl", v2OauthEndpointUrlBuilder.Uri.AbsoluteUri },
                        },
                };

                context.GetService<IConfigurationStore>().SaveV2Credential(credDataV2);
            }
            catch (Exception ex)
            {
                trace.Error("Fail to migrate .credentials to use endpoint in Token service.");
                trace.Error(ex);
            }
        }
    }
}
