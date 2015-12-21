using Microsoft.Owin;
//using Microsoft.Owin.Security.Jwt;
using Owin;
using System.Web.Http;


[assembly: OwinStartup(typeof(Doppel.Api.Startup))]

namespace Doppel.Api
{
    public partial class Startup
    {
        
        public void Configuration(IAppBuilder app)
        {
            HttpConfiguration httpConfig = new HttpConfiguration();
            //ConfigureOAuthTokenGeneration(app);
            //ConfigureOAuthTokenConsumption(app);

            ConfigureWebApi(httpConfig);

            //app.UseCors(Microsoft.Owin.Cors.CorsOptions.AllowAll);

            //app.UseWebApi(httpConfig);
            ConfigureAuth(app);

        }
    }
}
