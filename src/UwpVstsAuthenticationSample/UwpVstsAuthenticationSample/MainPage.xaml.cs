using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.Security.Authentication.Web;
using Windows.UI.Popups;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;

// The Blank Page item template is documented at http://go.microsoft.com/fwlink/?LinkId=402352&clcid=0x409

namespace UwpVstsAuthenticationSample
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainPage : Page
    {
        public MainPage()
        {
            this.InitializeComponent();
        }

        private async void AuthenticateButton_Click(object sender, RoutedEventArgs e)
        {
            // NOTE: This code is not secure! A more ideal implemtnation would be to proxy the OAuth flow
            // throuhg a web application so that the client secret can be kept confidential and then just
            // return the access token to the client when requested. This obviously requires more
            // infrastructure.
            
            // You get these by registering your application here: https://app.vsaex.visualstudio.com/app/register
            var clientID = "your-client-id";
            var clientSecret = "your-client-secret";
            var authorizationCodeCallbackUrl = "https://some.url/doesnt-need-to-exist";

            var authorizationCodeCallbackUri = new Uri(authorizationCodeCallbackUrl);

            var authorizationCodeRequestUrl = $"https://app.vssps.visualstudio.com/oauth2/authorize?client_id={clientID}&response_type=Assertion&state=none&scope=vso.profile&redirect_uri={authorizationCodeCallbackUrl}";
            var authorizationCodeRequestUri = new Uri(authorizationCodeRequestUrl);

            // The WAB takes care of popping up a dialog to auth against the endpoint provided above
            // and then automatically terminates when VSTS attempts to redirect to the specified
            // callback URL. WAB returns the redirect URL where you can extract the authorization code.
            var authenticationResult = await WebAuthenticationBroker.AuthenticateAsync(
                WebAuthenticationOptions.None,
                authorizationCodeRequestUri,
                authorizationCodeCallbackUri
                );

            // Make sure it all worked.
            if (authenticationResult.ResponseStatus != WebAuthenticationStatus.Success)
            {
                var errorDialog = new MessageDialog($"Authentication failed with: {authenticationResult.ResponseStatus}", "Authentication Failed");
                await errorDialog.ShowAsync();
                return;
            }

            // Extract the auth code.
            var actualAuthorizationCodeCallbackUri = new Uri(authenticationResult.ResponseData);
            var decoder = new WwwFormUrlDecoder(actualAuthorizationCodeCallbackUri.Query);
            var authorizationCode = decoder.GetFirstValueByName("code");

            // Setup to use the auth code to get an access token.
            var accessTokenCallbackUrl = "https://some.url/doesnt-need-to-exist";
            var accessTokenRequestUrl = "https://app.vssps.visualstudio.com/oauth2/token";
            var accessTokenRequestUri = new Uri(accessTokenRequestUrl);

            var client = new HttpClient();

            var accessTokenRequestPayload = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                new KeyValuePair<string, string>("client_assertion", clientSecret),
                new KeyValuePair<string, string>("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                new KeyValuePair<string, string>("assertion", authorizationCode),
                new KeyValuePair<string, string>("redirect_uri", accessTokenCallbackUrl)
            });

            // Request the access token.
            var accessTokenResponse = await client.PostAsync(
                accessTokenRequestUri,
                accessTokenRequestPayload
                );

            // Parse the response into JSON.
            var accessTokenResponsePayload = await accessTokenResponse.Content.ReadAsStringAsync();
            JObject parsedAccessTokenResponse = JObject.Parse(accessTokenResponsePayload);

            // These are the important values (there is also an expiry date which is useful if you want to
            // use the refresh token.
            var accessToken = parsedAccessTokenResponse["access_token"].Value<string>(); // Use this as the bearer token for requests.
            var refreshToken = parsedAccessTokenResponse["refresh_token"].Value<string>(); // Use this token to request another access token when the one above expires.

            // Now lets use the token to make a request to the VSTS REST API, passing the token in using the Bearer scheme.
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            var profileResponse = await client.GetAsync("https://app.vssps.visualstudio.com/_apis/profile/profiles/me?api-version=1.0");
            var profileResonsePayload = await profileResponse.Content.ReadAsStringAsync();

            // Popups!
            var profileResponseDialog = new MessageDialog(profileResonsePayload);
            await profileResponseDialog.ShowAsync();
        }
    }
}
