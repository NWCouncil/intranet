using Microsoft.Owin;
using Owin;

// Added these for Okta
using System.Collections.Generic;
using System.Configuration;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using IdentityModel.Client;
using System.Security.Claims;
using System;
using System.Linq;
using Microsoft.AspNet.Identity.Owin;
using System.Threading.Tasks;
using UmbracoIdentity;
using intranet.Models.UmbracoIdentity;
using intranet;
using Umbraco.Core.Composing;
using System.Web.Security;

[assembly: OwinStartup("MyOwinStartup", typeof(MyOwinStartup))]
namespace intranet
{
    public class MyOwinStartup : UmbracoIdentityOwinStartupBase
    {
        private readonly string clientId = ConfigurationManager.AppSettings["okta:ClientId"];
        private readonly string redirectUri = ConfigurationManager.AppSettings["okta:RedirectUri"];
        private readonly string authority = ConfigurationManager.AppSettings["okta:OrgUri"];
        private readonly string clientSecret = ConfigurationManager.AppSettings["okta:ClientSecret"];
        private readonly string postLogoutRedirectUri = ConfigurationManager.AppSettings["okta:PostLogoutRedirectUri"];

        protected override void ConfigureUmbracoUserManager(IAppBuilder app)
        {
            base.ConfigureUmbracoUserManager(app);

            //Single method to configure the Identity user manager for use with Umbraco
            app.ConfigureUserManagerForUmbracoMembers<UmbracoApplicationMember>();

            //Single method to configure the Identity user manager for use with Umbraco
            app.ConfigureRoleManagerForUmbracoMembers<UmbracoApplicationRole>();
        }

        protected override void ConfigureUmbracoAuthentication(IAppBuilder app)
        {
            base.ConfigureUmbracoAuthentication(app);

            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            var cookieOptions = CreateFrontEndCookieAuthenticationOptions();

            // You can change the cookie options here. The cookie options will be automatically set
            // based on what is configured in the security section of umbracoSettings.config and the web.config.
            // For example:
            // cookieOptions.CookieName = "testing";
            // cookieOptions.ExpireTimeSpan = TimeSpan.FromDays(20);

            cookieOptions.Provider = new CookieAuthenticationProvider
            {
                // Enables the application to validate the security stamp when the user 
                // logs in. This is a security feature which is used when you 
                // change a password or add an external login to your account.  
                OnValidateIdentity = SecurityStampValidator
                        .OnValidateIdentity<UmbracoMembersUserManager<UmbracoApplicationMember>, UmbracoApplicationMember, int>(
                            TimeSpan.FromMinutes(30),
                            (manager, user) => user.GenerateUserIdentityAsync(manager),
                            identity =>
                            {
                                var email = identity.Claims.FirstOrDefault(c => c.Type == "email")?.Value;
                                var member = Current.Services.MemberService.GetByEmail(email);

                                return member.Id;
                            })
            };

            app.UseCookieAuthentication(cookieOptions, PipelineStage.Authenticate);

            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ApplicationCookie);

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret,
                Authority = authority,
                RedirectUri = redirectUri,
                ResponseType = OpenIdConnectResponseType.CodeIdToken,
                Scope = OpenIdConnectScope.OpenIdProfile + " email",
                PostLogoutRedirectUri = postLogoutRedirectUri,
                TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name"
                },

                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    AuthorizationCodeReceived = async n =>
                    {
                        // Exchange code for access and ID tokens
                        var tokenClient = new TokenClient(authority + "/v1/token", clientId, clientSecret);
                        var tokenResponse = await tokenClient.RequestAuthorizationCodeAsync(n.Code, redirectUri);

                        if (tokenResponse.IsError)
                        {
                            throw new Exception(tokenResponse.Error);
                        }

                        var userInfoClient = new UserInfoClient(authority + "/v1/userinfo");
                        var userInfoResponse = await userInfoClient.GetAsync(tokenResponse.AccessToken);
                        var claims = new List<Claim>();
                        claims.AddRange(userInfoResponse.Claims);
                        claims.Add(new Claim("id_token", tokenResponse.IdentityToken));
                        claims.Add(new Claim("access_token", tokenResponse.AccessToken));

                        if (!string.IsNullOrEmpty(tokenResponse.RefreshToken))
                        {
                            claims.Add(new Claim("refresh_token", tokenResponse.RefreshToken));
                        }

                        n.AuthenticationTicket.Identity.AddClaims(claims);

                        var email = claims.FirstOrDefault(c => c.Type == "email")?.Value;
                        var name = claims.FirstOrDefault(c => c.Type == "name")?.Value;

                        // create member if not exists already.
                        var member = Services.MemberService.GetByEmail(email);
                        if (member == null)
                        {
                            member = Services.MemberService.CreateMember(email, email, name, "Member");
                            Services.MemberService.Save(member);
                        }

                        // login memeber
                        FormsAuthentication.SetAuthCookie(email, true);

                        return;
                    },

                    RedirectToIdentityProvider = n =>
                    {
                        // If signing out, add the id_token_hint
                        if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.Logout)
                        {
                            var idTokenClaim = n.OwinContext.Authentication.User.FindFirst("id_token");

                            if (idTokenClaim != null)
                            {
                                n.ProtocolMessage.IdTokenHint = idTokenClaim.Value;
                            }

                        }

                        return Task.CompletedTask;
                    }
                },
            });

            //// Back-office: Active directory authentication
            //ConfigureBackofficeActiveDirectoryPasswords(app);
        }

        //private void ConfigureBackofficeActiveDirectoryPasswords(IAppBuilder app)
        //{
        //    app.ConfigureUserManagerForUmbracoBackOffice<BackOfficeUserManager, BackOfficeIdentityUser>(
        //        RuntimeState,
        //        GlobalSettings,
        //        (options, context) =>
        //        {
        //            var membershipProvider = MembershipProviderExtensions.GetUsersMembershipProvider().AsUmbracoMembershipProvider();

        //            var userManager = BackOfficeUserManager.Create(
        //                options,
        //                Services.UserService,
        //                Services.MemberTypeService,
        //                Services.EntityService,
        //                Services.ExternalLoginService,
        //                membershipProvider,
        //                Mapper,
        //                UmbracoSettings.Content,
        //                GlobalSettings
        //            );
        //            userManager.BackOfficeUserPasswordChecker = new ActiveDirectoryBackOfficeUserPasswordChecker();
        //            return userManager;
        //        });
        //}
    }


}