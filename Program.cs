using AuthApi.Data;
using AuthApi.Options;
using AuthApi.Services;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

/* This registers PasswordService with ASP.NET Core’s dependency injection (DI) container.
- IPasswordService is the service contract—the interface your code can depend on.
- PasswordService is the concrete class ASP.NET Core will create to fulfill that contract.
- AddSingleton means the container creates one PasswordService instance and reuses it wherever 
    IPasswordService is requested, for the lifetime of the application. */
builder.Services.AddSingleton<IPasswordService, PasswordService>();
builder.Services.Configure<JwtOptions>(
    builder.Configuration.GetSection(JwtOptions.Section));

/* Adjust the MySqlServerVersion to match your server. I use a fixed version 
instead of AutoDetect so the app doesn’t need a live DB connection at startup. */
var connectionString = builder.Configuration.GetConnectionString("Default")
    ?? throw new InvalidOperationException("Missing connection string 'Default'.");

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseMySql(connectionString, new MySqlServerVersion(new Version(8, 4, 0))));

builder.Services.AddControllers();

var app = builder.Build();

app.UseHttpsRedirection();
app.MapControllers();

app.Run();