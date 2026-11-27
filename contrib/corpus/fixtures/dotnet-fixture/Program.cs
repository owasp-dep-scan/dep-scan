using Newtonsoft.Json;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// The /weather route's handler serialises with Newtonsoft.Json, so the
// route-to-package label names pkg:nuget/Newtonsoft.Json.
app.MapGet("/weather", () =>
{
    var forecast = new { Summary = "mild", Temperature = 21 };
    return Results.Text(JsonConvert.SerializeObject(forecast), "application/json");
});

// The /health route uses nothing but the framework, so its label holds no
// third-party package.
app.MapGet("/health", () => Results.Ok("healthy"));

app.Run();
