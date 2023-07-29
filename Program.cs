/* ������ ������� (��� ������������ �����������
 
����� appsettings.Development.json � appsettings.json �������������� ������ ��������� ���:

{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "AllowedHosts": "*"
}

{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  }
}
 
*/
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.ComponentModel.Design;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection.Metadata.Ecma335;
using System.Security.Claims;
using System.Text;
using System.Xml.Linq;
using static System.Net.WebRequestMethods;

namespace ASP.NET_Core_7// ���� � ������ "��������" ��� ������ ��������������, �� � ���� � ���� ����� middleware. ���� � ������ "���������", �� ���� ����� ��������� ���������
{
    public class Program
    {
        public static List<Person> persons = new List<Person>(20);
        public static int applicationInt = 16;
        public static WebApplication app;
        public static WebApplicationBuilder builder;
        public static void Main(string[] args)
        {
            builder = WebApplication.CreateBuilder(args);// ��� ���������� �� ������������ ������ CreateBuilder() ������ WebApplication (����� - ����� ����������). ���� ����� ������� ������ ������ WebApplicationBuilder (����� - ����� ����������� ����������) �� ��������� ��������� � ������������. ���� �������� ������ ���������������� �������������� ����������� ����������, �� ��������� ������� ����� ��������� ��� ���� ����������. ��� �����, ���� ���������� �������� ������ ���������� ���������� ������ args, � ��� ������, ��� ��������� ��������� � ���������������� ���������� ����� ������� ��� �� ����� ������� ���������� �� �������. ������ ���������� CMD ����� �������� ������ ������ WebApplicationOption
            builder.Services.AddDbContext<MyDbContext>(ServiceLifetime.Scoped, ServiceLifetime.Scoped);// ���� �� ��� ��� Transient, �� ��� ����������� ����� ������ ���������� �������� �� ���������� �� ��� ������� ���������� ���������. ������ ��� �����, ����� � ���������� ���������� ��� ������� ��������� �� (����� ��������� ������������ �� �������� �������-��������� ���), � �������� ����������� ������� (���������� �� � HttpContext.Item)
            builder.Services.AddAuthorization();// � �������� ����� ������ ����� �������� ������� � ���������� ���� AuthorizationOptions ��� ��������� � ���������������� �����������
            builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(options =>
            {
                options.LoginPath = "/unauthorized";
                options.AccessDeniedPath = "/accessdenied";
            });

            app = builder.Build();// ������ ����������� ����������, ����������, ������ ���� ���������� �� ��������� ���������� ���������������� �������������, �������� ����������� ��������� ������. ����� ���������� ����������� ��� ���������� ���������� �������, ��������� ���������, ��������� �������� � �.�.

            // ��� ���� ��� API
            //for (int i = 0; i < 5; i++)
            //    persons.Add(new Person(null, -1));

            AuthenticationJob();

            app.Run();
        }
        public static void AuthenticationJob()// ���� �� ���� �����������, HttpContext.SignInAsync(ClaimsPrincipal) ����� ������������� ������� ������ ���� ������������������ Cookies. �. �. ���� ������� ���� ����� ��������� ���, �� ������ Cookies ����� ������� ���������
        {
            // ��� ����� �������� �� builder.Build()
            //builder.Services.AddDbContext<MyDbContext>(ServiceLifetime.Transient);

            // � ��� ����� � ������ ��� �������� �� (�. �. ���� �� ���)
            //MyDbContext db = app.Services.GetService<MyDbContext>();
            //db.Database.EnsureCreated();
            //db.Dispose();

            // JWT-������. ��� ���� �������� �� ���������� ����������
            //builder.Services.AddAuthorization();// � �������� ����� ������ ����� �������� ������� � ���������� ���� AuthorizationOptions ��� ��������� � ���������������� �����������
            //Microsoft.AspNetCore.Authentication.AuthenticationBuilder authenticationBuilder = builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme);// � ��������� ����� ������ ���������� ����� �������������� (� ������ ������ �������������� ����� ��������� �� ����� JWT-�������), � ����� ����� �������� ������� � ���������� ���� AuthenticationOptions ��� ��������� ��������� � ���������������� ��������������. �������� ��������� �������������� ���������� ����������������� � ���������� ��������������� �����, ������������ ��� �������������� 
            //authenticationBuilder.AddJwtBearer(options =>// � ��� � ��������� �����. ��������� �� ��� ������ ����, �������� ���������� ���� AuthenticationBuilder, ����� ������������� - � ������ ��� ������ ��� �����������
            //{
            //    options.TokenValidationParameters = new TokenValidationParameters
            //    {
            //        ValidateIssuer = true,// ���������, ����� �� �������������� �������� ��� ��������� ������
            //        ValidIssuer = AuthenticationOptions.ISSUER,// ������, �������������� ��������
            //        ValidateAudience = true,// ����� �� �������������� ����������� ������
            //        ValidAudience = AuthenticationOptions.AUDIENCE,// ��������� ����������� ������
            //        ValidateLifetime = true,// ����� �� �������������� ����� �������������
            //        IssuerSigningKey = AuthenticationOptions.GetSymmetricSecurityKey(),// ��������� ����� ������������
            //        ValidateIssuerSigningKey = true,// ��������� ����� ������������
            //        ClockSkew = TimeSpan.FromSeconds(5)// �������� ������ ���������� ����������� (������������ �����������������) ����� 5 ������
            //    };
            //});

            // ����. ��� ���� �������� �� ���������� ����������
            //builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(options =>
            //{
            //    options.LoginPath = "/unauthorized";
            //    options.AccessDeniedPath = "/accessdenied";
            //});

            app.UseAuthentication();
            app.UseAuthorization();
            app.UseMiddleware<DatabaseBegin>();

            app.Map("/Db/Login/User/{name}", async (HttpContext context, MyDbContext db, string name) =>// �������� ��� ������ ���������� � ����� ��������� � ����� �����
            {
                // ������ � ������ ������������� ������ ���������� JWT-����� ���� ��� ������������ ������������ ������������ (�. �. �� ��������� ����� ����� ������������� ���� �� ��������� �������)
                //User user = db.Users.AsNoTracking().ToList().FirstOrDefault(x => x.Name == name);
                //if (user is null) return Results.Unauthorized();
                //List<Claim> claims = new List<Claim> { new Claim(ClaimTypes.Name, user.Name) };// ����� ������, "��������" ������ � ���. ���������� � ���
                //JwtSecurityToken jwt = new JwtSecurityToken(issuer: AuthenticationOptions.ISSUER, audience: AuthenticationOptions.AUDIENCE, claims: claims, expires: DateTime.UtcNow.Add(TimeSpan.FromMinutes(2)), signingCredentials: new SigningCredentials(AuthenticationOptions.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256));// ����� ������� ����� 2 ������ � ��� ����� 5 ������ ������ ����������
                //string encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);
                //var response = new { access_token = encodedJwt, username = user.Name };
                ////context.SignInAsync(ClaimsPrincipal);// ������ ������ ��������� ������������������ ����
                //return Results.Json(response);

                // ��������� ��������� JWT-������� ������ ������� ��� ������ �� ���������� :(. �� ������ - �� ������� �������� ����� ������ ������� ���������� � �������

                // ��������� � ��������
                User user = db.Users.AsNoTracking().ToList().FirstOrDefault(x => x.Name == name);
                if (user is null) return Results.Unauthorized();
                List<Claim> UkPassportClaims = new List<Claim> { new Claim(ClaimTypes.Name, name + " UK"), new Claim("IdentityName", "UkPassport"), new Claim("IdentityRole", "User") };
                ClaimsIdentity identity = new ClaimsIdentity(UkPassportClaims, "Cookies", "IdentityName", "IdentityRole");// 2-�� �������� ������ �������� �������� AuthenticationType. ��� ������ ������, �� ���� ��� �������� �� ��������, �� ������� ����� ��������� �� ������������������� (�. �. �������� IsAuthenticated ���� false � ������� Authorize �� ��������� ������� � ����� ��������� ���������); 3-�� �������� ������ �������� �������� NameType. ��� ��������� � �������� Name, ��� ���������� ������� Claim.Value ������� ���������� ������� Claim, ��� �������� Claim.Type ����� ClaimsIdentity.NameType. �� ��������� NameType ����� DefaultNameClaimType (�. �. ���� ������� Claim(ClaimsIdentity.DefaultNameClaimType, "ClaimsIdentity name!") � ���������� � �������� ClaimsIdentity.Name, �� ��� ������ "ClaimsIdentity name!". 4-�� �������� ������ �������� RoleType. ��� ��������, ��� � � 3-�� ���������� - �� ����� �������� ������ �����, �� ������ ��� �������� ��� ������ �� ��������, ������ ��� ��� �������� ������ - ���� ����� � �������� Authorize. �� ��������� ����� DefaultRoleClaimType
                ClaimsPrincipal userClient = new ClaimsPrincipal(identity);
                await context.SignInAsync(userClient);
                return Results.Redirect("/");
            });
            app.Map("/Db/Login/Admin/{name}", async (HttpContext context, MyDbContext db, string name) =>// �������� ��� ������ ���������� � ����� ��������� � ����� ������
            {
                // ������ � ������ ������������� ������ ���������� JWT-����� ���� ��� ������������ ������������ ������������ (�. �. �� ��������� ����� ����� ������������� ���� �� ��������� �������)
                //User user = db.Users.AsNoTracking().ToList().FirstOrDefault(x => x.Name == name);
                //if (user is null) return Results.Unauthorized();
                //List<Claim> claims = new List<Claim> { new Claim(ClaimTypes.Name, user.Name) };// ����� ������, "��������" ������ � ���. ���������� � ���
                //JwtSecurityToken jwt = new JwtSecurityToken(issuer: AuthenticationOptions.ISSUER, audience: AuthenticationOptions.AUDIENCE, claims: claims, expires: DateTime.UtcNow.Add(TimeSpan.FromMinutes(2)), signingCredentials: new SigningCredentials(AuthenticationOptions.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256));// ����� ������� ����� 2 ������ � ��� ����� 5 ������ ������ ����������
                //string encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);
                //var response = new { access_token = encodedJwt, username = user.Name };
                ////context.SignInAsync(ClaimsPrincipal);// ������ ������ ��������� ������������������ ����
                //return Results.Json(response);

                // ��������� ��������� JWT-������� ������ ������� ��� ������ �� ���������� :(. �� ������ - �� ������� �������� ����� ������ ������� ���������� � �������

                // ��������� � ��������
                User user = db.Users.AsNoTracking().ToList().FirstOrDefault(x => x.Name == name);
                if (user is null) return Results.Unauthorized();
                List<Claim> RfPassportClaims = new List<Claim> { new Claim(ClaimTypes.Name, name + " RF"), new Claim("IdentityName", "RfPassport"), new Claim("IdentityRole", "Admin") };
                ClaimsIdentity identity = new ClaimsIdentity(RfPassportClaims, "Cookies", "IdentityName", "IdentityRole");// 3-�� �������� (CookiesName) �������� ��� ��� �����������, �������� ������� ����� ������������ ������� �������� ClaimsIdentity.Name (� ������ ������ ����� ������ �������� ������� ���������� ����������� � ������ CookiesName), 2-�� - ��� �������������� ��� ������������� (� ������ ������ ����, �� ��� ����� ���� ������), 4-�� - ���� ������������� (����� ��������, �. �. ����� ���� ����������� � ��������� Authorization)
                ClaimsPrincipal userClient = new ClaimsPrincipal(identity);
                await context.SignInAsync(userClient);
                return Results.Redirect("/");
            });
            app.Map("/Db/Login/AdminAndUser/{name}", async (HttpContext context, MyDbContext db, string name) =>// �������� ��� ������ ���������� � ����� ���������� � ������ ����� � ������
            {
                // ������ � ������ ������������� ������ ���������� JWT-����� ���� ��� ������������ ������������ ������������ (�. �. �� ��������� ����� ����� ������������� ���� �� ��������� �������)
                //User user = db.Users.AsNoTracking().ToList().FirstOrDefault(x => x.Name == name);
                //if (user is null) return Results.Unauthorized();
                //List<Claim> claims = new List<Claim> { new Claim(ClaimTypes.Name, user.Name) };// ����� ������, "��������" ������ � ���. ���������� � ���
                //JwtSecurityToken jwt = new JwtSecurityToken(issuer: AuthenticationOptions.ISSUER, audience: AuthenticationOptions.AUDIENCE, claims: claims, expires: DateTime.UtcNow.Add(TimeSpan.FromMinutes(2)), signingCredentials: new SigningCredentials(AuthenticationOptions.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256));// ����� ������� ����� 2 ������ � ��� ����� 5 ������ ������ ����������
                //string encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);
                //var response = new { access_token = encodedJwt, username = user.Name };
                ////context.SignInAsync(ClaimsPrincipal);// ������ ������ ��������� ������������������ ����
                //return Results.Json(response);

                // ��������� ��������� JWT-������� ������ ������� ��� ������ �� ���������� :(. �� ������ - �� ������� �������� ����� ������ ������� ���������� � �������

                // ��������� � ��������
                User user = db.Users.AsNoTracking().ToList().FirstOrDefault(x => x.Name == name);
                if (user is null) return Results.Unauthorized();
                List<Claim> RfPassportClaims = new List<Claim> { new Claim(ClaimTypes.Name, name + " RF"), new Claim("IdentityName", "RfPassport"), new Claim("IdentityRole", "Admin") };
                List<Claim> UkPassportClaims = new List<Claim> { new Claim(ClaimTypes.Name, name + " UK"), new Claim("IdentityName", "UkPassport"), new Claim("IdentityRole", "User") };
                List<ClaimsIdentity> identities = new List<ClaimsIdentity>
                {
                    new ClaimsIdentity(RfPassportClaims, "Cookies", "IdentityName", "IdentityRole"),// 3-�� �������� (CookiesName) �������� ��� ��� �����������, �������� ������� ����� ������������ ������� �������� ClaimsIdentity.Name (� ������ ������ ����� ������ �������� ������� ���������� ����������� � ������ CookiesName), 2-�� - ��� �������������� ��� ������������� (� ������ ������ ����, �� ��� ����� ���� ������), 4-�� - ���� ������������� (����� ��������, �. �. ����� ���� ����������� � ��������� Authorization)
                    new ClaimsIdentity(UkPassportClaims, "Cookies", "IdentityName", "IdentityRole")
                };
                ClaimsPrincipal userClient = new ClaimsPrincipal(identities);
                await context.SignInAsync(userClient);
                return Results.Redirect("/");
            });
            app.Map("/AuthorizeUser", [Authorize(Roles = "User")] async (HttpContext context) =>// ������� ������ ���� ���� ������� � ����� �����
            {
                context.Response.ContentType = "text/html; charset=utf-8";
                StringBuilder res = new StringBuilder(256);
                IEnumerable<ClaimsIdentity> identities = context.User.Identities;
                foreach (ClaimsIdentity identity in identities)
                {
                    res.Append($"<h2>Identity name: {identity.Name}</h2><p>User name: {identity.FindFirst(ClaimTypes.Name).Value}</p><p>Identity role: {identity.FindFirst(identity.RoleClaimType).Value}</p><p>Identity authentication type: {identity.AuthenticationType}</p>");
                }
                await context.Response.WriteAsync(res.ToString());
            });
            app.Map("/AuthorizeAdmin", [Authorize(Roles = "Admin")] async (HttpContext context) =>// ������� ������ ���� ���� ������� � ����� ������
            {
                context.Response.ContentType = "text/html; charset=utf-8";
                StringBuilder res = new StringBuilder(256);
                IEnumerable<ClaimsIdentity> identities = context.User.Identities;
                foreach (ClaimsIdentity identity in identities)
                {
                    res.Append($"<h2>Identity name: {identity.Name}</h2><p>User name: {identity.FindFirst(ClaimTypes.Name).Value}</p><p>Identity role: {identity.FindFirst(identity.RoleClaimType).Value}</p><p>Identity authentication type: {identity.AuthenticationType}</p>");
                }
                await context.Response.WriteAsync(res.ToString());
            });
            app.Map("/AuthorizeAdminOrUser", [Authorize(Roles = "Admin, User")] async (HttpContext context) =>// ������� ������ ���� ���� ������� � ����� ����� ���� ������� � ����� ������
            {
                context.Response.ContentType = "text/html; charset=utf-8";
                StringBuilder res = new StringBuilder(256);
                IEnumerable<ClaimsIdentity> identities = context.User.Identities;
                foreach (ClaimsIdentity identity in identities)
                {
                    res.Append($"<h2>Identity name: {identity.Name}</h2><p>User name: {identity.FindFirst(ClaimTypes.Name).Value}</p><p>Identity role: {identity.FindFirst(identity.RoleClaimType).Value}</p><p>Identity authentication type: {identity.AuthenticationType}</p>");
                }
                await context.Response.WriteAsync(res.ToString());
            });
            app.Map("/AuthorizeSimple", [Authorize] async (HttpContext context) =>// ������� � ����� �������������� ��������� (������� ����� ������ �����������, ���� ��� �������� AuthenticationType �� ������)
            {
                context.Response.ContentType = "text/html; charset=utf-8";
                StringBuilder res = new StringBuilder(256);
                IEnumerable<ClaimsIdentity> identities = context.User.Identities;
                foreach (ClaimsIdentity identity in identities)
                {
                    res.Append($"<h2>Identity name: {identity.Name}</h2><p>User name: {identity.FindFirst(ClaimTypes.Name).Value}</p><p>Identity role: {identity.FindFirst(identity.RoleClaimType).Value}</p><p>Identity authentication type: {identity.AuthenticationType}</p>");
                }
                await context.Response.WriteAsync(res.ToString());
            });
            app.Map("/unauthorized", async (HttpContext context) =>
            {
                context.Response.StatusCode = 403;
                await context.Response.WriteAsync("Unauthorized");
            });
            app.Map("/accessdenied", async (HttpContext context) =>
            {
                context.Response.StatusCode = 403;
                await context.Response.WriteAsync("Access Denied");
            });
            app.MapGet("/logout", async (HttpContext context) =>
            {
                await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                return "logout";
            });
            app.Map("/Db/Recreate", async (MyDbContext db) =>
            {
                db.Database.EnsureDeleted();
                db.Database.EnsureCreated();
            });
            app.MapGet("/Db/{id:int}", async (HttpContext context, MyDbContext db, int id) =>// ������ ��� Scoped
            {
                List<User> res = db.Users.AsNoTracking().ToList();
                if (id > 0)
                {
                    await context.Response.WriteAsJsonAsync(res.FirstOrDefault(x => x.Id == id));
                    return;
                }
                await context.Response.WriteAsJsonAsync(res);
            });
            app.MapPost("/Db/{length:int}", async (MyDbContext db, int length) =>// ������ ��� Scoped
            {
                length = length < 1 ? 1 : length;
                db.Users.AddRange(Tools.UserRandom(length));
                db.SaveChanges();
                return 200;
            });
        }
        public static void DatabaseJob()
        {
            // ��� ����� �������� �� builder.Build()
            //builder.Services.AddDbContext<MyDbContext>(ServiceLifetime.Transient);

            // � ��� ����� � ������ ��� �������� �� (�. �. ���� �� ���)
            //MyDbContext db = app.Services.GetService<MyDbContext>();
            //db.Database.EnsureCreated();
            //db.Dispose();

            app.UseMiddleware<DatabaseBegin>();

            app.Map("/Db/Recreate", async (MyDbContext db) =>
            {
                db.Database.EnsureDeleted();
                db.Database.EnsureCreated();
            });
            app.MapGet("/Db/{id:int}", async (HttpContext context, MyDbContext db, int id) =>// ������ ��� Scoped
            {
                List<User> res = db.Users.AsNoTracking().ToList();
                if (id > 0)
                {
                    await context.Response.WriteAsJsonAsync(res.FirstOrDefault(x => x.Id == id));
                    return;
                }
                await context.Response.WriteAsJsonAsync(res);
            });
            app.MapPost("/Db/{length:int}", async (MyDbContext db, int length) =>// ������ ��� Scoped
            {
                length = length < 1 ? 1 : length;
                db.Users.AddRange(Tools.UserRandom(length));
                db.SaveChanges();
                return 200;
            });
        }
        public static void StateCookiesSessions()// ���� �� ��� ������ � ������� ��������, �� ��� �� ��������� �����
        {
            void Cookies()// ������: IRequestCookieCollection (HttpContext.Request.Cookies) ������������ ��� ��������� ����, � IResponseCookieCollection (HttpContext.Response.Cookies) ��� ��������������� ��� (���������� � ��������)
            {
                app.Use(async (context, next) =>
                {
                    if (context.Request.Query.Count > 0)
                        await next.Invoke();
                    else
                    {
                        context.Response.StatusCode = 400;
                        await context.Response.WriteAsync("Request parameters required");
                    }
                });
                app.MapGet("/deleteCookie", async (context) =>// ����������� ����������� ��������� �������� �����
                {
                    context.Response.Cookies.Delete(context.Request.Query.Keys.First());
                    await context.Response.WriteAsync("Delete complete");
                });
                app.MapGet("/setCookie", async (context) =>// ����������� ����������� ��������� ���������� �����
                {
                    string cookieName = context.Request.Query.Keys.First(), cookieValue = context.Request.Query[cookieName];
                    context.Response.Cookies.Append(cookieName, cookieValue);
                    await context.Response.WriteAsync("Append complete");
                });
                app.MapGet("/getCookie", async (context) =>
                {
                    string name, cookie = context.Request.Query.Keys.First();
                    IRequestCookieCollection cookies = context.Request.Cookies;
                    if (cookie == "all")
                    {
                        name = "";
                        foreach (string enumerator in cookies.Keys)
                        {
                            name += cookies[enumerator];
                        }
                    }
                    else
                    {
                        if (cookies.ContainsKey(cookie))
                            name = cookies[cookie];
                        else
                            name = "cookies \"name\" not found!";
                    }
                    await context.Response.WriteAsync($"Cookies \"name\": {name}");
                });
            }
            void State()
            {
                app.Use(async (context, next) =>
                {
                    context.Items["text"] = "Hello from HttpContext.Items";// ������� Items ������ HttpContext ��������� ���� ��������� �� ���������� ���� ��������� ������� �� ��������� � ���������, ����������� ��� ����� ��������� ������ ������� ����� ����������� � ���������� ��������� ������� (������ � ������ ��������� ������ �������)
                    await next.Invoke();
                });
                app.Run(async (context) => await context.Response.WriteAsync($"Text: {context.Items["text"]}"));
            }
            Cookies();
        }
        public static void Routing()
        {
            async Task RouteHandler(HttpContext context, IMyService myService, string id, string name, string standart, string? nullable, string tail)
            {
                myService.Job($"URL options: id = {id}; name = {name}; standart = {standart}; nullable = {nullable ?? "null"}; tail = {tail}");
                await context.Response.WriteAsync($"URL options: id = {id}; name = {name}; standart = {standart}; nullable = {nullable ?? "null"}; tail = {tail}");
                return;
            }
            void Options()
            {
                app.MapGet("/options/{id:int}/{name}/{standart:bool=true}/{nullable?}/{**tail=nothing}", RouteHandler);// ���� �������� ���� ��������� ������ ����, �� � ���������� ����� �������� "��� ����" - �. �. ��� ���������������� URL-������������� (� ��� ������, ��� ������ �������� ��� ��������� US-ASCII, ����� �� ����)
            }
            Options();
        }
        public static void Services()
        {
            void SingleRegistration()
            {
                builder.Services.AddSingleton<IMyService, MyServiceOne>();// ������ � ��������-����������� IMyService ������������ ��������� ���������� - MyServiceOne. ������ ���� �������� ������ IMyService, ����� ����� ���� � ������� MyServiceOne
                builder.Services.AddScoped<MyServicesContainer>();// ASP.NET Core ��� �������� ����������� �������-������ MyServicesContainer ���� ����� �������� � ��� ����������� ����������, �������������� � �������� ����������� IMyService (������ ����, ���� �� ������ - ����� ������)
                
                //app.MapGet("/", (IMyService ims) =>// ����� ����������� ������� � ���� ����� ���������� �� �������� ����� ��� �������� ������� (������, ��� �� �������� ����������� app.Services.GetService)
                //{
                //    ims.Job("Abobbbb");
                //});

                app.Run(async context =>// ���� � ���������� middleware-����������� ��������� ���� ������������������ ��������, �� ASP.NET Core ����� ��� �������� ��� ���������� �� ������ (����������) ���������� - �. �. �� ����� ��������. ���� �������������� ������ ����������� ������ �� Scoped ��������� �������� ����� �������
                {
                    // ��� ��� ������ ������ �� �������� � (��������������) Scoped ���������
                    //var scp = app.Services.CreateScope();
                    //MyServicesContainer myServicesContainer = scp.ServiceProvider.GetService<MyServicesContainer>();
                    //myServicesContainer.Print();
                    //scp.Dispose();

                    // �������� ������ � Transient � Singleton ���������
                    MyServicesContainer myServicesContainer = app.Services.GetService<MyServicesContainer>();
                    myServicesContainer.Text = "MessageCustom";
                    myServicesContainer.Print();
                });
            }
            void MultipleRegistration()
            {
                builder.Services.AddTransient<IMyService, MyServiceOne>();
                builder.Services.AddTransient<IMyService, MyServiceTwo>();
                //app.UseMiddleware<MultipleRegistrationMiddleware>();
            }
            MultipleRegistration();
        }
        public static async Task GettingFiles(HttpContext context)
        {
            context.Response.ContentType = "text/html; charset=utf-8";
            if (context.Request.Path == "/upload" && context.Request.Method == "POST")
            {
                IFormFileCollection files = context.Request.Form.Files;
                FileStream fileStream;
                foreach (IFormFile file in files)
                {
                    fileStream = new FileStream($"uploads/{file.FileName}", FileMode.Create);
                    await file.CopyToAsync(fileStream);// ���� �� ���������� �� ���� ����� � ����������� await'��
                    fileStream.Dispose();
                }
            }
            else
                await context.Response.SendFileAsync("indexFile.html");
            return;
        }
        public static async Task Api(HttpContext context)// API ����� ��������� ������: "/api/{int id}?params". ���� ������ id ������� ������������ �������� (������), �� ���������� "�������" ������� ���� ��-�� "��" (�. �. ������������ ������ ����� ��� ������, ��������� ���������). ����� ��������� "�������� � ����", ����� ������� ����� ���������� �������� id (� ������� 0), ��� ���� ��� ������ �������� ���������� ������� ������ ("idCond" � "ageCond") ��� ���������� ����� ����������� �� "�����" (�. �. ����� ������, ������� ��������, ������ ���������). ������ ������� ��� ��������� ���� ������� � id ������ 37 � age ������ 10: "/api/37?age=10&idCond=less&ageCond=more"
        {
            if (context.Request.Path.ToString().Length > 5)// ��������� ����� ������ 5 ����� �� ��������
            {
                if (context.Request.Path.ToString().Substring(0, 5) == "/api/")// ������������ ����� ���������� � ���?
                {
                    if (context.Request.Method == "GET")// � ��� �� ���������� ������� ���?
                    {
                        Tools.Comparison operationId = Tools.Nothing, operationAge = Tools.Nothing;// �� ��������� ������� ������ ��� � � ������ �������� ����� ��� ������
                        int id, age;

                        if (int.TryParse(context.Request.Path.ToString().Substring(5), out id))// �� ���������?
                        {
                            operationId = Tools.Equals;// ����������� ������ � ���������� �� - ������ � ��, ������ ����������
                            if (context.Request.QueryString.HasValue)// ��������� ����?
                            {
                                IQueryCollection options = context.Request.Query;
                                if (options.ContainsKey("idCond"))// ������� ������ �� ����?
                                {
                                    if (options["idCond"] == "more")// ���� ���� � ���������� - �������� �� ���������
                                        operationId = Tools.More;
                                    else if (options["idCond"] == "less")
                                        operationId = Tools.Less;
                                }
                                if (options.ContainsKey("age"))// ����� �� ����� � ��������� ������ ���� ������� �� ������������
                                {
                                    if (int.TryParse(options["age"], out age))
                                    {
                                        operationAge = Tools.Equals;
                                        if (options.ContainsKey("ageCond"))
                                        {
                                            if (options["ageCond"] == "more")
                                                operationAge = Tools.More;
                                            else if (options["ageCond"] == "less")
                                                operationAge = Tools.Less;
                                        }
                                    }
                                    else
                                        age = 0;
                                }
                                else
                                    age = 0;
                            }
                            else
                                age = 0;
                        }
                        else// �� �� ��������� - ������ �� ��������������� � ����� ��� ������
                            age = 0;
                        await context.Response.WriteAsJsonAsync(persons.GetPerson(id, age, operationId, operationAge));
                        return;
                    }
                }
            }
        }
        public static void MiddlewareConveyor()
        {
            /*app.MapWhen// MapWhen ������ �� �� �����, ��� � UseWhen, �� ������ "��������" ������ ����� ���� �������� �����. �. �. ���� ������ ������������ ���� �����, �� ��� ��������������� ������� �������� ����� ������ ������ ��������� (��� �����), � ��������� �� ����� (�������� �� next.Invoke())
            (
                context =>
                {
                    Console.WriteLine();
                    Console.WriteLine();
                    Console.WriteLine("MapWhen. Checking the pipeline branching condition!");
                    if (context.Request.QueryString.HasValue)
                        if (context.Request.Query.ContainsKey("UseWhen"))
                            return true;
                    return false;
                },
                appBuilder =>
                {
                    string timeUseWhen = DateTime.Now.ToShortTimeString();
                    Console.WriteLine("MapWhen. Branch built!");
                    appBuilder.Use
                    (
                        async (context, next) =>
                        {
                            string timeUseWhenMiddleware = DateTime.Now.ToShortTimeString();
                            Console.WriteLine($"MapWhen. MapWhen middleware work before. Time builder: {timeUseWhen}");
                            next.Invoke();
                            Console.WriteLine($"MapWhen. MapWhen middleware work after. Time component: {timeUseWhenMiddleware}");
                        }
                    );
                }
            );*/
            app.Use(ConveyorMiddleware.FirstComponentDelegate);
            app.Use(ConveyorMiddleware.SecondComponentDelegate);
            app.UseWhen// ������ �������� ����� ������ - �����, ������������ bool � ����������� HttpContext. �� ��������� ����� ������ ASP.NET Core ����������, � ����� ������� ����� ������������ ��������� (� ������ ������ ������������ ������������ ����� ���� �������������� ��������� ��������� ��� �������� � URL-���������� "UseWhen"). ������ �������� - ����� "���������� �����" - ���������� void � ��������� IApplicationBuilder
            (
                context =>// ���� �������� ����� ����� ������ ���������� ��� ������� ������� ����� �������� "��������" ��������� ����� ������������ (�. �. ����� ������� �������� � ����� ������� ASP.NET Core ���������, ����� �� ���������� ��� ����� (�. �., ��������, ��� ����� ���� ������ ������ ����������) �� ����� �������� ����������)
                {   //
                    //Console.WriteLine();
                    //Console.WriteLine();
                    //Console.WriteLine("UseWhen. Checking the pipeline branching condition!");
                    if (context.Request.QueryString.HasValue)
                        if (context.Request.Query.ContainsKey("UseWhen"))
                            return true;
                    return false;
                },
                appBuilder =>// ��� �����������, ����������� � ���� ������ "���������� �����" �������� � ���� ������ ����� ���������� ������� ����. �. �. ���� ����� ������ �����, � ���������� ��� �� � ���� ���������� ��� ����������� ������� ��� ASP.NET Core ���� ��������� �������
                {
                    string timeUseWhen = DateTime.Now.ToShortTimeString();// "����������� �����" ����������� �������� ����� ������� ����������!
                    //Console.WriteLine("UseWhen. Branch built!");
                    appBuilder.Use
                    (
                        async (context, next) =>
                        {
                            string timeUseWhenMiddleware = DateTime.Now.ToShortTimeString();
                            Console.WriteLine($"UseWhen. UseWhen middleware work before. Time builder: {timeUseWhen}");
                            next.Invoke();
                            Console.WriteLine($"UseWhen. UseWhen middleware work after. Time component: {timeUseWhenMiddleware}");
                        }
                    );
                }
            );// ���� �� � ������� ��� ����� ������ �����������, �� � ������� ���������� ������� ��� ���������� �� ������
            app.Map// ������ �� ��, ��� � MapWhen, �� ������ ��� ������������� URL-������. ����� ����� ������ ������� ����� ���������� �������� �����
            (
                "/MapBranch",
                appBuilder =>
                {
                    appBuilder.Map// ��� ����� (������, ������ ������������) ����� ������������ ������� � "/MapBranch/Subbranch"
                    (
                        "/Subbranch",
                        appBuilder =>
                        {
                            appBuilder.Use
                            (
                                async (context, next) =>
                                {
                                    Console.WriteLine($"MapSubbranch. MapSubbranch middleware work before");
                                    next.Invoke();
                                    Console.WriteLine($"MapSubbranch. MapSubbranch middleware work after");
                                }
                            );
                        }
                    );
                    appBuilder.Use
                    (
                        async (context, next) =>
                        {
                            Console.WriteLine($"MapBranch. MapBranch middleware work before");
                            next.Invoke();
                            Console.WriteLine($"MapBranch. MapBranch middleware work after");
                        }
                    );
                }
            );

            // ����� � �������� ����������. ��� ������������ ���������� ��� ��������� � ����������� ���� ����
            //app.UseMiddleware<TokenMiddleware>("Allowed");// ������������ ����� � �������� middleware-����������. ���� ������� � ������� (���������� ����������) - "[URL]?token=Allowed"
            //app.Run(async (context) => await context.Response.WriteAsync("The request contains the correct parameter"));

            //app.Run(ConveyorMiddleware.LastComponentDelegate);
        }
        public static void RoutingBasics_20_06_23()
        {
            //app.MapGet("/", () => "Hello World!");// ����� MapGet() ������������ GET-URL-������ � ������ ��������� ���������� (�������) �� ������ ��������� (� ������ ������ ��� ������ ����� ������-���������). �. �. ��� GET-������� � ����� ���������� ������������ "Hello World!". MapGet() ���������� � Microsoft.AspNetCore.Builder.EndpointRouteBuilderExtensions, � ����� �������� ������ ���������� IEndpointRouteBuilder, ������������� ���������� �� ������������� ����������. ������-�� � Microsoft.AspNetCore.Builder.EndpointRouteBuilderExtensions ���� ����� ����� � ������ ��� ���� �������� ���� IEndpointRouteBuilder, ������������, � ������ �������, ��������������� ������������� (� �������, ������ ����������), ����� ����������� ��� ����� �������������, ���������� �������. �� � ������ ���������� ���������� ������������ ������ ����� ������, ������������� ����������� � �������� ������� ��������� ���� ����������
            Microsoft.AspNetCore.Builder.EndpointRouteBuilderExtensions.MapGet(app, "/", () =>// ������ ������ ��������� ������ �� ������ ����
            {
                string all = "Urls: ";
                foreach (string url in app.Urls)
                    all += url;
                all += " " + Thread.CurrentThread.ManagedThreadId;
                Stopwatch sw = new Stopwatch();
                sw.Start();
                while (sw.ElapsedMilliseconds < 5000) ;
                //Thread.Sleep(5000);
                return all;
            });
            app.MapGet("/Urls", () =>// �� ��������� �������� �� ����� MapGet-URL-������� ASP.NET Core ������ ����� �������� ����� �� ����, ������ ���� �� ����� ������ ������ ��� ���� ������ (�� ����, ��� ���������� ������), �� ASP.NET Core �������� ��� ��������� � ������� � ���� �� ������ ������� ������ (������� ��� �� �������� ���������), ��� ����� (� ������ �������) ������ ������, ��������� "/Urls" ����� ����� 10 ������, ������ 5 (��� ��� ������������) - 5 ������ ����������� ������� (��� ������ ���� ���� ����� � �������) � ���� 5 ������. ������ ��������� ������� ����� �������� ���������� �� ������ ����� ������� (�. �. ���� ����������� ��� � ������ ������, �� � ������� "/", �� �� ������� ���� ����� �����, �� ������ 10 ������ � �������, �. �. ASP.NET Core ������� ��� ������ ����� (�� ���� �� ����� �� ����� �� ������ "���� ����� �� ������"))
            {
                string all = "Urls: ";
                foreach (string url in app.Urls)// Urls ���������� �� ��� �������������� ��������, � ������ ������, ����������� � ������� (� ���� ������ ��� 2 ���������� ������ "localhost/" �� �� ������ ������ � ���������� (������ ���� �� https, ������ �� http))
                    all += url;
                all += " " + Thread.CurrentThread.ManagedThreadId;
                Stopwatch sw = new Stopwatch();
                sw.Start();
                while (sw.ElapsedMilliseconds < 5000) ;
                //Thread.Sleep(5000);
                return all;
            });// UPD: ���� ������ MapGet �������� � �������� ����������� ������� RequestDelegate (� async-await, ���� �����), ��, ��������, �������� ������������ ���������� ��������� ���� ��������. UPD: ������, ��� �� ASP.NET Core ������ (��-�� ��� ���-���� ���������), � � ������� - ������ ������� ���� �� ������ ������� ����������� � ������ �������, ������ � ��������� � ������ ������� �� ���� ������� ������ ������� (���� ����) � ASP.NET Core ���������� ���, ���� �� �����, ��� ���� ������, � ���� ������� ��� �� ������ �������� (� �������, ����, ��� � ����), �� � ASP.NET Core ������, ��� � �������������, 3 ������� � �� ��������� �� �� 3 �������
        }
        public static async Task FormsAndPostQuery(HttpContext context)
        {
            context.Response.Headers.ContentType = "text/html; charset=utf-8";
            if (context.Request.Path == "/postuser")
            {
                if (context.Request.Method != "POST")
                {
                    context.Response.StatusCode = 405;
                    await context.Response.WriteAsync($"<div><p>Only the POST method can be applied to the specified resource</p></div>");
                    return;// ��-�� ���� ���� ������ return'�� ����� await'�� ��� ���������� middleware �� ������ "����������" � ��������, ������ ���� ��� �������, �. �. �������� � return'�� ������ ��������� ��������� ����������� ����� ����� � � ����� ������. ���� ������ ��� ���������� ����� ����������� ����� ������ (������ ��� ������ "��������" �� ����������� �������� ������, �. �. await'�, �����������, �� ����������� �����)
                }

                IFormCollection form = null;
                try
                {
                    form = context.Request.Form;
                }
                catch
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsync($"<div><p>Failed to get the form. Possible problem: invalid request format. Must be: \"name=[nameValue]&age=[ageValue]\"</p></div>");
                    return;
                }

                if (!form.ContainsKey("name") || !form.ContainsKey("age") || !form.ContainsKey("languages"))
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsync($"<div><p>Invalid request format. Must be: \"name=[nameValue]&age=[ageValue]&languages=[languagesValue]<&languages=[languagesValue]&languages=[languagesValue]...>\"</p></div>");
                    return;
                }
                else
                {
                    string name = form["name"], age = form["name"];
                    string[] languages = form["languages"];
                    string langList = "";
                    foreach (var lang in languages)
                        langList += $" {lang}";
                    context.Response.StatusCode = 200;
                    await context.Response.WriteAsync($"<div><p>Name: {name}</p><p>Age: {age}</p><p>Languages: {langList}</p></div>");
                    return;
                }
            }
            else
            {
                await context.Response.SendFileAsync("index.html");
                return;
            }
        }
        public static async Task SendingFiles(HttpContext context)
        {
            string DownloadFile()
            {
                context.Response.Headers.ContentDisposition = "attachment; filename=BrutalSkala.png";
                return "Skala.png";
            }

            string SimpleSending() => "Skala.png";// �������� �� ��������� ����� �����, � ������ ��������� �� �� ������� (��� ���������� ���� �������� ���� ����� (�� ��������, ��� � ��� �������� HTML-������ ����� "ContentType: text/html"))

            await context.Response.SendFileAsync(DownloadFile());
            return;
        }
        public static async Task HttpContextMiddleware(HttpContext context)// ����� Run() �������� � ����� ��������� ������� RequestDelegate, ����������� ��������� ������ ��������� �������� ������ � ��������� �������
        {
            void ResponseHeaders()// ���������� � ����������� ������. ������ ��� ������ ������ ������������ �������� �� ������ � ���������� �������
            {
                HttpResponse response = context.Response;
                response.Headers.ContentLanguage = "ru-RU";
                response.Headers.ContentType = "text/plain; charset=utf-8";
                response.Headers.Append("secret-id", "256");// ���������� ���������� ������
                response.StatusCode = 404;// ���������� ����� �������
                //response.ContentType = "text/html; charset=utf-8";// ��� ����� ��� Html
                //response.Headers.ContentLength = 106;// ���� �������� ����� ��������� ����� ������ ���-�� ������������ � ���� ������ ��������, �� ���������� ������ �� ������� ������� ASP.NET Core � ���������� ������. �� ��������� ���� ��������� ����������� � ������ ���� ����� "Transfer-Encoding: chunked", �������������� �������� ����� ������ ������� ������������ ��� (�� HTTP/2 �� ���������� �� ��, �� ������, � ����������� ���-�� ���)
            }
            string RequestHeaders()// �������� ��� ��������� �������
            {
                context.Response.ContentType = "text/html; charset=utf-8";
                StringBuilder stringBuilder = new StringBuilder("<table>", 700);
                foreach (var header in context.Request.Headers)
                {
                    stringBuilder.Append($"<tr><td>{header.Key}</td><td>{header.Value}</td></tr>");
                }
                stringBuilder.Append("</table>");
                return stringBuilder.ToString();
            }
            string RequestMyHeader()// ������� ��������� ���������� ������ �������
            {
                StringValues myHeaderBuf;
                string myHeader = "No such header";
                if (context.Request.Headers.TryGetValue("MyHeader", out myHeaderBuf))
                    myHeader = myHeaderBuf.ToString();
                return myHeader;
            }
            string RequestQueryString()
            {
                context.Response.ContentType = "text/html; charset=utf-8";
                StringBuilder stringBuilder = new StringBuilder("<h1>Query string non-parse: " + context.Request.QueryString + "</h1><table>", 256);
                foreach (var param in context.Request.Query)
                {
                    stringBuilder.Append($"<tr><td>{param.Key}</td><td>{param.Value}</td></tr>");
                }
                stringBuilder.Append("</table>");
                return stringBuilder.ToString();
            }

            await context.Response.WriteAsync(RequestQueryString());
            return;
            //await context.Response.WriteAsync(context.Request.Path);// ���������� � ���� ������. �������� "context.Request.Path" ���������� ������ ���� � �������������� ������� (��������, ��� ��� ��� ������ ������ ����� ����� �������� ���� �������������)
        }
    }
}