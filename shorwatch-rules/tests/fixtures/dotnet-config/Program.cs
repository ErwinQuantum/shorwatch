using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);
var algorithm = builder.Configuration["Jwt:Algorithm"];
var credentials = new SigningCredentials(new SymmetricSecurityKey(new byte[32]), algorithm);
