using Acme.Auth;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection(JwtOptions.SectionName));
builder.Services.AddOptions<SafeOptions>().BindConfiguration("Safe");
