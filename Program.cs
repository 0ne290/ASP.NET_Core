/* Старые конфиги (для стандартного логирования
 
Файлы appsettings.Development.json и appsettings.json соответственно раньше выглядили так:

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

namespace ASP.NET_Core_7// Если я говорю "конвейер" без явного маршрутизатора, то я имею в виду голый middleware. Если я говорю "компонент", то имею ввиду компонент конвейера
{
    public class Program
    {
        public static List<Person> persons = new List<Person>(20);
        public static int applicationInt = 16;
        public static WebApplication app;
        public static WebApplicationBuilder builder;
        public static void Main(string[] args)
        {
            builder = WebApplication.CreateBuilder(args);// Все начинается со статического метода CreateBuilder() класса WebApplication (далее - класс приложения). Этот метод создает объект класса WebApplicationBuilder (далее - класс построителя приложения) на основании аргумента в конструкторе. Этот аргумент задает конфигурационные характеристики построителя приложения, на основании которых будет построено уже само приложение. Как видно, этим аргументом является массив параметров консольной строки args, а это значит, что первичные настройку и конфигурирование приложения можно сделать еще на этапе запуска приложения из консоли. Вместо параметров CMD можно передать объект класса WebApplicationOption
            builder.Services.AddDbContext<MyDbContext>(ServiceLifetime.Scoped, ServiceLifetime.Scoped);// Если бы тут был Transient, то при стандартной форме записи миддлваров контекст БД создавался бы для каждого компонента конвейера. Обойти это можно, убрав в параметрах миддлваров тип сервиса контекста БД (чтобы провайдер зависимостей не создавал сервисы-контексты сам), и управляя контекстами вручную (передавать их в HttpContext.Item)
            builder.Services.AddAuthorization();// В параметр этого метода можно передать делегат с параметром типа AuthorizationOptions для настройки и конфигурирования авторизации
            builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(options =>
            {
                options.LoginPath = "/unauthorized";
                options.AccessDeniedPath = "/accessdenied";
            });

            app = builder.Build();// Теперь построитель приложения, собственно, строит само приложение на основании внутренних конфигурационных характеристик, заданных аргументами командной строки. Класс приложения применяется для управления обработкой запроса, установки маршрутов, получения сервисов и т.д.

            // Это надо для API
            //for (int i = 0; i < 5; i++)
            //    persons.Add(new Person(null, -1));

            AuthenticationJob();

            app.Run();
        }
        public static void AuthenticationJob()// Судя по моим наблюдениям, HttpContext.SignInAsync(ClaimsPrincipal) может устанавливать клиенту только один аутентификационный Cookies. Т. е. если вызвать этот метод несколько раз, то первый Cookies будет заменен последним
        {
            // Это нужно добавить до builder.Build()
            //builder.Services.AddDbContext<MyDbContext>(ServiceLifetime.Transient);

            // А это после и только для создания БД (т. е. пока ее нет)
            //MyDbContext db = app.Services.GetService<MyDbContext>();
            //db.Database.EnsureCreated();
            //db.Dispose();

            // JWT-токены. Это надо добавить до построения приложения
            //builder.Services.AddAuthorization();// В параметр этого метода можно передать делегат с параметром типа AuthorizationOptions для настройки и конфигурирования авторизации
            //Microsoft.AspNetCore.Authentication.AuthenticationBuilder authenticationBuilder = builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme);// В параметры этого метода передается схема аутентификации (в данном случае аутентификация будет проходить по схеме JWT-токенов), а также можно передать делегат с параметром типа AuthenticationOptions для ПЕРВИЧНОЙ настройки и конфигурирования аутентификации. Основная настройка аутентификации происходит конфигурированием и настройкой соответствующей схемы, используемой для аутентификации 
            //authenticationBuilder.AddJwtBearer(options =>// А вот и настройка схемы. Разносить на две строки кода, создавая переменную типа AuthenticationBuilder, вовсе необязательно - я сделал так просто для наглядности
            //{
            //    options.TokenValidationParameters = new TokenValidationParameters
            //    {
            //        ValidateIssuer = true,// указывает, будет ли валидироваться издатель при валидации токена
            //        ValidIssuer = AuthenticationOptions.ISSUER,// строка, представляющая издателя
            //        ValidateAudience = true,// будет ли валидироваться потребитель токена
            //        ValidAudience = AuthenticationOptions.AUDIENCE,// установка потребителя токена
            //        ValidateLifetime = true,// будет ли валидироваться время существования
            //        IssuerSigningKey = AuthenticationOptions.GetSymmetricSecurityKey(),// установка ключа безопасности
            //        ValidateIssuerSigningKey = true,// валидация ключа безопасности
            //        ClockSkew = TimeSpan.FromSeconds(5)// Истекшие токены становятся невалидными (окончательно недействительными) через 5 секунд
            //    };
            //});

            // Куки. Это надо добавить до построения приложения
            //builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(options =>
            //{
            //    options.LoginPath = "/unauthorized";
            //    options.AccessDeniedPath = "/accessdenied";
            //});

            app.UseAuthentication();
            app.UseAuthorization();
            app.UseMiddleware<DatabaseBegin>();

            app.Map("/Db/Login/User/{name}", async (HttpContext context, MyDbContext db, string name) =>// Эндпоинт для выдачи принципала с одним идентисом с ролью юзера
            {
                // Легкий и сугубо академический способ отправлять JWT-токен даже без полноценного формирования пользователя (т. е. на основании этого бреда разграничение прав не получится сделать)
                //User user = db.Users.AsNoTracking().ToList().FirstOrDefault(x => x.Name == name);
                //if (user is null) return Results.Unauthorized();
                //List<Claim> claims = new List<Claim> { new Claim(ClaimTypes.Name, user.Name) };// Грубо говоря, "описание" токена и доп. информация о нем
                //JwtSecurityToken jwt = new JwtSecurityToken(issuer: AuthenticationOptions.ISSUER, audience: AuthenticationOptions.AUDIENCE, claims: claims, expires: DateTime.UtcNow.Add(TimeSpan.FromMinutes(2)), signingCredentials: new SigningCredentials(AuthenticationOptions.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256));// Токен истечет через 2 минуты и еще через 5 секунд станет невалидным
                //string encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);
                //var response = new { access_token = encodedJwt, username = user.Name };
                ////context.SignInAsync(ClaimsPrincipal);// Легкий способ добавлять аутентификационный куки
                //return Results.Json(response);

                // Отправить несколько JWT-токенов одному клиенту так просто не получилось :(. Ну ничего - на крайняк идентисы можно самому вручную отправлять и парсить

                // Принципал в печенюху
                User user = db.Users.AsNoTracking().ToList().FirstOrDefault(x => x.Name == name);
                if (user is null) return Results.Unauthorized();
                List<Claim> UkPassportClaims = new List<Claim> { new Claim(ClaimTypes.Name, name + " UK"), new Claim("IdentityName", "UkPassport"), new Claim("IdentityRole", "User") };
                ClaimsIdentity identity = new ClaimsIdentity(UkPassportClaims, "Cookies", "IdentityName", "IdentityRole");// 2-ый параметр задает значение свойству AuthenticationType. Это просто строка, но если это значение не задается, то идентис будет считаться не аутентифицированным (т. е. свойство IsAuthenticated даст false и атрибут Authorize не пропустит клиента с таким фуфельным идентисом); 3-ий параметр задает значение свойству NameType. При обращении к свойству Name, оно попытается вернуть Claim.Value первого найденного объекта Claim, чье свойство Claim.Type равно ClaimsIdentity.NameType. По умолчанию NameType равен DefaultNameClaimType (т. е. если создать Claim(ClaimsIdentity.DefaultNameClaimType, "ClaimsIdentity name!") и обратиться к свойству ClaimsIdentity.Name, то оно вернет "ClaimsIdentity name!". 4-ый параметр задает свойство RoleType. Тут ситуация, как и с 3-им параметром - по этому свойству ищется клейм, но только это значение так просто не получишь, потому что его основная задача - быть ролью в атрибуте Authorize. По умолчанию равен DefaultRoleClaimType
                ClaimsPrincipal userClient = new ClaimsPrincipal(identity);
                await context.SignInAsync(userClient);
                return Results.Redirect("/");
            });
            app.Map("/Db/Login/Admin/{name}", async (HttpContext context, MyDbContext db, string name) =>// Эндпоинт для выдачи принципала с одним идентисом с ролью админа
            {
                // Легкий и сугубо академический способ отправлять JWT-токен даже без полноценного формирования пользователя (т. е. на основании этого бреда разграничение прав не получится сделать)
                //User user = db.Users.AsNoTracking().ToList().FirstOrDefault(x => x.Name == name);
                //if (user is null) return Results.Unauthorized();
                //List<Claim> claims = new List<Claim> { new Claim(ClaimTypes.Name, user.Name) };// Грубо говоря, "описание" токена и доп. информация о нем
                //JwtSecurityToken jwt = new JwtSecurityToken(issuer: AuthenticationOptions.ISSUER, audience: AuthenticationOptions.AUDIENCE, claims: claims, expires: DateTime.UtcNow.Add(TimeSpan.FromMinutes(2)), signingCredentials: new SigningCredentials(AuthenticationOptions.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256));// Токен истечет через 2 минуты и еще через 5 секунд станет невалидным
                //string encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);
                //var response = new { access_token = encodedJwt, username = user.Name };
                ////context.SignInAsync(ClaimsPrincipal);// Легкий способ добавлять аутентификационный куки
                //return Results.Json(response);

                // Отправить несколько JWT-токенов одному клиенту так просто не получилось :(. Ну ничего - на крайняк идентисы можно самому вручную отправлять и парсить

                // Принципал в печенюху
                User user = db.Users.AsNoTracking().ToList().FirstOrDefault(x => x.Name == name);
                if (user is null) return Results.Unauthorized();
                List<Claim> RfPassportClaims = new List<Claim> { new Claim(ClaimTypes.Name, name + " RF"), new Claim("IdentityName", "RfPassport"), new Claim("IdentityRole", "Admin") };
                ClaimsIdentity identity = new ClaimsIdentity(RfPassportClaims, "Cookies", "IdentityName", "IdentityRole");// 3-ий параметр (CookiesName) содержит имя тех утверждений, значения которых будут возвращаться вызовом свойства ClaimsIdentity.Name (в данном случае вызов вернет значение первого найденного утверждения с именем CookiesName), 2-ой - тип аутентификации для удостоверения (в данном случае куки, но это всего лишь строка), 4-ый - роль удостоверения (имеет значение, т. к. может быть использован с атрибутом Authorization)
                ClaimsPrincipal userClient = new ClaimsPrincipal(identity);
                await context.SignInAsync(userClient);
                return Results.Redirect("/");
            });
            app.Map("/Db/Login/AdminAndUser/{name}", async (HttpContext context, MyDbContext db, string name) =>// Эндпоинт для выдачи принципала с двумя идентисами с ролями юзера и админа
            {
                // Легкий и сугубо академический способ отправлять JWT-токен даже без полноценного формирования пользователя (т. е. на основании этого бреда разграничение прав не получится сделать)
                //User user = db.Users.AsNoTracking().ToList().FirstOrDefault(x => x.Name == name);
                //if (user is null) return Results.Unauthorized();
                //List<Claim> claims = new List<Claim> { new Claim(ClaimTypes.Name, user.Name) };// Грубо говоря, "описание" токена и доп. информация о нем
                //JwtSecurityToken jwt = new JwtSecurityToken(issuer: AuthenticationOptions.ISSUER, audience: AuthenticationOptions.AUDIENCE, claims: claims, expires: DateTime.UtcNow.Add(TimeSpan.FromMinutes(2)), signingCredentials: new SigningCredentials(AuthenticationOptions.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256));// Токен истечет через 2 минуты и еще через 5 секунд станет невалидным
                //string encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);
                //var response = new { access_token = encodedJwt, username = user.Name };
                ////context.SignInAsync(ClaimsPrincipal);// Легкий способ добавлять аутентификационный куки
                //return Results.Json(response);

                // Отправить несколько JWT-токенов одному клиенту так просто не получилось :(. Ну ничего - на крайняк идентисы можно самому вручную отправлять и парсить

                // Принципал в печенюху
                User user = db.Users.AsNoTracking().ToList().FirstOrDefault(x => x.Name == name);
                if (user is null) return Results.Unauthorized();
                List<Claim> RfPassportClaims = new List<Claim> { new Claim(ClaimTypes.Name, name + " RF"), new Claim("IdentityName", "RfPassport"), new Claim("IdentityRole", "Admin") };
                List<Claim> UkPassportClaims = new List<Claim> { new Claim(ClaimTypes.Name, name + " UK"), new Claim("IdentityName", "UkPassport"), new Claim("IdentityRole", "User") };
                List<ClaimsIdentity> identities = new List<ClaimsIdentity>
                {
                    new ClaimsIdentity(RfPassportClaims, "Cookies", "IdentityName", "IdentityRole"),// 3-ий параметр (CookiesName) содержит имя тех утверждений, значения которых будут возвращаться вызовом свойства ClaimsIdentity.Name (в данном случае вызов вернет значение первого найденного утверждения с именем CookiesName), 2-ой - тип аутентификации для удостоверения (в данном случае куки, но это всего лишь строка), 4-ый - роль удостоверения (имеет значение, т. к. может быть использован с атрибутом Authorization)
                    new ClaimsIdentity(UkPassportClaims, "Cookies", "IdentityName", "IdentityRole")
                };
                ClaimsPrincipal userClient = new ClaimsPrincipal(identities);
                await context.SignInAsync(userClient);
                return Results.Redirect("/");
            });
            app.Map("/AuthorizeUser", [Authorize(Roles = "User")] async (HttpContext context) =>// Пускаем только если есть идентис с ролью юзера
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
            app.Map("/AuthorizeAdmin", [Authorize(Roles = "Admin")] async (HttpContext context) =>// Пускаем только если есть идентис с ролью админа
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
            app.Map("/AuthorizeAdminOrUser", [Authorize(Roles = "Admin, User")] async (HttpContext context) =>// Пускаем только если есть идентис с ролью юзера либо идентис с ролью админа
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
            app.Map("/AuthorizeSimple", [Authorize] async (HttpContext context) =>// Пускаем с любым авторизованным идентисом (идентис будет всегда авторизован, если его свойство AuthenticationType не пустое)
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
            app.MapGet("/Db/{id:int}", async (HttpContext context, MyDbContext db, int id) =>// Версия для Scoped
            {
                List<User> res = db.Users.AsNoTracking().ToList();
                if (id > 0)
                {
                    await context.Response.WriteAsJsonAsync(res.FirstOrDefault(x => x.Id == id));
                    return;
                }
                await context.Response.WriteAsJsonAsync(res);
            });
            app.MapPost("/Db/{length:int}", async (MyDbContext db, int length) =>// Версия для Scoped
            {
                length = length < 1 ? 1 : length;
                db.Users.AddRange(Tools.UserRandom(length));
                db.SaveChanges();
                return 200;
            });
        }
        public static void DatabaseJob()
        {
            // Это нужно добавить до builder.Build()
            //builder.Services.AddDbContext<MyDbContext>(ServiceLifetime.Transient);

            // А это после и только для создания БД (т. е. пока ее нет)
            //MyDbContext db = app.Services.GetService<MyDbContext>();
            //db.Database.EnsureCreated();
            //db.Dispose();

            app.UseMiddleware<DatabaseBegin>();

            app.Map("/Db/Recreate", async (MyDbContext db) =>
            {
                db.Database.EnsureDeleted();
                db.Database.EnsureCreated();
            });
            app.MapGet("/Db/{id:int}", async (HttpContext context, MyDbContext db, int id) =>// Версия для Scoped
            {
                List<User> res = db.Users.AsNoTracking().ToList();
                if (id > 0)
                {
                    await context.Response.WriteAsJsonAsync(res.FirstOrDefault(x => x.Id == id));
                    return;
                }
                await context.Response.WriteAsJsonAsync(res);
            });
            app.MapPost("/Db/{length:int}", async (MyDbContext db, int length) =>// Версия для Scoped
            {
                length = length < 1 ? 1 : length;
                db.Users.AddRange(Tools.UserRandom(length));
                db.SaveChanges();
                return 200;
            });
        }
        public static void StateCookiesSessions()// Сюда бы еще работу с сессией добавить, но это не настолько важно
        {
            void Cookies()// Выводы: IRequestCookieCollection (HttpContext.Request.Cookies) используется для получения куки, а IResponseCookieCollection (HttpContext.Response.Cookies) для манипулирования ими (добавление и удаление)
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
                app.MapGet("/deleteCookie", async (context) =>// Реализовать возможность массового удаления куков
                {
                    context.Response.Cookies.Delete(context.Request.Query.Keys.First());
                    await context.Response.WriteAsync("Delete complete");
                });
                app.MapGet("/setCookie", async (context) =>// Реализовать возможность массового добавления куков
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
                    context.Items["text"] = "Hello from HttpContext.Items";// Словарь Items класса HttpContext сохраняет свое состояние на протяжении всей обработки запроса от миддлвара к миддлвару, обеспечивая тем самым механизмы обмена данными между миддлварами и сохранения состояние сервера (только в рамках обработки одного запроса)
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
                app.MapGet("/options/{id:int}/{name}/{standart:bool=true}/{nullable?}/{**tail=nothing}", RouteHandler);// Если написать одну звездочку вместо двух, то в переменную уйдет значение "как есть" - т. е. без предварительного URL-декодирования (а это значит, что вместо символов вне кодировки US-ASCII, будут их коды)
            }
            Options();
        }
        public static void Services()
        {
            void SingleRegistration()
            {
                builder.Services.AddSingleton<IMyService, MyServiceOne>();// Теперь с сервисом-интерфейсом IMyService асоциирована конретная реализация - MyServiceOne. Теперь если получать сервис IMyService, будем иметь дело с классом MyServiceOne
                builder.Services.AddScoped<MyServicesContainer>();// ASP.NET Core при создании экземпляров сервиса-класса MyServicesContainer сама будет помещать в его конструктор реализацию, асоциированную с сервисом интерфейсом IMyService (строка выше, если ее убрать - будет ошибка)
                
                //app.MapGet("/", (IMyService ims) =>// После регистрации сервиса к нему можно обращаться из конечных точек без создания объекта (считай, что за кулисами выполняется app.Services.GetService)
                //{
                //    ims.Job("Abobbbb");
                //});

                app.Run(async context =>// Если в параметрах middleware-компонентов указывать типы зарегистрированных сервисов, то ASP.NET Core будет сам вызывать эти компоненты от нужных (правильных) параметров - т. е. от типов сервисов. Этот автоматический способ налаживания работы со Scoped сервисами является самым простым
                {
                    // Код для ручной работы со скоупами и (соответственно) Scoped сервисами
                    //var scp = app.Services.CreateScope();
                    //MyServicesContainer myServicesContainer = scp.ServiceProvider.GetService<MyServicesContainer>();
                    //myServicesContainer.Print();
                    //scp.Dispose();

                    // Работает только с Transient и Singleton сервисами
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
                    await file.CopyToAsync(fileStream);// Пора бы избавиться от этих тупых и бесполезных await'ов
                    fileStream.Dispose();
                }
            }
            else
                await context.Response.SendFileAsync("indexFile.html");
            return;
        }
        public static async Task Api(HttpContext context)// API имеет следующий формат: "/api/{int id}?params". Если вместо id указать некорректное значение (строку), то произойдет "жесткая" выборка всех эл-ов "БД" (т. е. пользователю просто уйдут все записи, игнорируя параметры). Чтобы параметры "вступили в силу", нужно указать любое корректное значение id (к примеру 0), при этом без явного указания параметров условий отбора ("idCond" и "ageCond") они стандартно будут приниматься за "равно" (т. е. уйдут записи, имеющие значения, равные указанным). Пример запроса для получения всех записей с id меньше 37 и age больше 10: "/api/37?age=10&idCond=less&ageCond=more"
        {
            if (context.Request.Path.ToString().Length > 5)// Проверяем длину меньше 5 чтобы не багануло
            {
                if (context.Request.Path.ToString().Substring(0, 5) == "/api/")// Пользователь хочет обратиться к апи?
                {
                    if (context.Request.Method == "GET")// К апи он обращается методом гет?
                    {
                        Tools.Comparison operationId = Tools.Nothing, operationAge = Tools.Nothing;// По умолчанию условий отбора нет и в случае отправки уйдут все записи
                        int id, age;

                        if (int.TryParse(context.Request.Path.ToString().Substring(5), out id))// Ид корректен?
                        {
                            operationId = Tools.Equals;// Минимальный запрос с корректным ид - записи с ид, равным указанному
                            if (context.Request.QueryString.HasValue)// Параметры есть?
                            {
                                IQueryCollection options = context.Request.Query;
                                if (options.ContainsKey("idCond"))// Условие отбора ид есть?
                                {
                                    if (options["idCond"] == "more")// Если есть и корректное - свапнуть на указанное
                                        operationId = Tools.More;
                                    else if (options["idCond"] == "less")
                                        operationId = Tools.Less;
                                }
                                if (options.ContainsKey("age"))// Такая же херня с возрастом только плюс парсинг на корректность
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
                        else// Ид не корректен - запрос не модифицировался и уйдут все записи
                            age = 0;
                        await context.Response.WriteAsJsonAsync(persons.GetPerson(id, age, operationId, operationAge));
                        return;
                    }
                }
            }
        }
        public static void MiddlewareConveyor()
        {
            /*app.MapWhen// MapWhen делает то же самое, что и UseWhen, но только "обрубает" идущую после себя основную ветку. Т. е. если сейчас раскоментить этот метод, то при удовлетворяющих условию запросах будет вызван первый компонент (эта ветка), а остальные не будут (несмотря на next.Invoke())
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
            app.UseWhen// Первый параметр этого метода - метод, возвращающий bool и принимающий HttpContext. На основании этого метода ASP.NET Core определяет, в каких случаях будет разветвление конвейера (в данном случае разветвление представляет собой один дополнительный компонент конвейера для запросов с URL-параметром "UseWhen"). Второй параметр - метод "построения ветки" - возвращает void и принимает IApplicationBuilder
            (
                context =>// Этот условный метод будет всегда вызываться для каждого запроса после передачи "эстафеты" конвейера двумя компонентами (т. е. перед вызовом третьего и таким образом ASP.NET Core определит, нужно ли встраивать эту ветку (т. е., очевидно, тут может быть больше одного компонента) на место третьего компонента)
                {   //
                    //Console.WriteLine();
                    //Console.WriteLine();
                    //Console.WriteLine("UseWhen. Checking the pipeline branching condition!");
                    if (context.Request.QueryString.HasValue)
                        if (context.Request.Query.ContainsKey("UseWhen"))
                            return true;
                    return false;
                },
                appBuilder =>// Все манипуляции, проведенные в этом методе "построения ветки" вступают в силу только после соблюдения условия выше. Т. е. этот метод строит ветку, а встраивает уже ее в наше приложение для конкретного запроса сам ASP.NET Core если соблюдено условие
                {
                    string timeUseWhen = DateTime.Now.ToShortTimeString();// "Построитель ветки" запускается единожды после запуска приложения!
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
            );// Если бы я написал эту ветку первым компонентом, то в случаях соблюдения условия она вызывалась бы первой
            app.Map// Делает то же, что и MapWhen, но только для определенного URL-адреса. Ветка этого метода ЗАМЕНИТ собой оставшуюся основную ветку
            (
                "/MapBranch",
                appBuilder =>
                {
                    appBuilder.Map// Эта ветка (кстати, ВМЕСТО родительской) будет обрабатывать запросы к "/MapBranch/Subbranch"
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

            // Класс в качестве компонента. Для демонстрации закомменти все остальное и раскомменти этот блок
            //app.UseMiddleware<TokenMiddleware>("Allowed");// Регистрируем класс в качестве middleware-компонента. Ключ доступа к ресурсу (последнему компоненту) - "[URL]?token=Allowed"
            //app.Run(async (context) => await context.Response.WriteAsync("The request contains the correct parameter"));

            //app.Run(ConveyorMiddleware.LastComponentDelegate);
        }
        public static void RoutingBasics_20_06_23()
        {
            //app.MapGet("/", () => "Hello World!");// Метод MapGet() сопоставляет GET-URL-адресу в первом параметре обработчик (делегат) во втором параметре (в данном случае это просто сразу лямбда-выражение). Т. е. при GET-запросе к корню приложения напечатается "Hello World!". MapGet() содержится в Microsoft.AspNetCore.Builder.EndpointRouteBuilderExtensions, а также является частью интерфейса IEndpointRouteBuilder, определяющего функционал по маршрутизации приложения. Вообще-то в Microsoft.AspNetCore.Builder.EndpointRouteBuilderExtensions этот метод имеет в начале еще один параметр типа IEndpointRouteBuilder, определяющий, к какому объекту, поддерживающему маршрутизацию (к примеру, другое приложение), будет применяться эта самая маршрутизация, задаваемая методом. Но в классе приложения вызывается интерфейсная версия этого метода, автоматически указывающая в качестве первого параметра свое приложение
            Microsoft.AspNetCore.Builder.EndpointRouteBuilderExtensions.MapGet(app, "/", () =>// Второй способ выполнить работу на строке выше
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
            app.MapGet("/Urls", () =>// На обработку запросов по таким MapGet-URL-адресам ASP.NET Core скорее всего выделяет поток из пула, однако если по этому адресу придет еще один запрос (до того, как выполнился старый), то ASP.NET Core поместит его обработку в очередь к тому же самому первому потоку (который еще не закончил обработку), тем самым (в данном примере) второй клиент, ожидающий "/Urls" будет ждать 10 секунд, вместо 5 (как это задумывалось) - 5 секунд предыдущего клиента (наш клиент пока типа сидит в очереди) и свои 5 секунд. Однако остальные ресурсы будут работать независимо от потока этого ресурса (т. е. если подключится еще и третий клиент, но к ресурсу "/", то он получит свой ответ сразу, не ожидая 10 секунд в очереди, т. к. ASP.NET Core выделит ему другой поток (но судя по всему по такой же логике "один поток на ресурс"))
            {
                string all = "Urls: ";
                foreach (string url in app.Urls)// Urls возвращает не все обрабатываемые маршруты, а только домены, привязанные к серверу (в моем случае это 2 одинаковых адреса "localhost/" но по разным портам и протоколам (первый порт на https, второй на http))
                    all += url;
                all += " " + Thread.CurrentThread.ManagedThreadId;
                Stopwatch sw = new Stopwatch();
                sw.Start();
                while (sw.ElapsedMilliseconds < 5000) ;
                //Thread.Sleep(5000);
                return all;
            });// UPD: если методу MapGet передать в качестве обработчика делегат RequestDelegate (с async-await, само собой), то, возможно, совковый однопоточный долбаебизм описанный выше исчезнет. UPD: отмена, это не ASP.NET Core плохой (он-то как раз-таки суперский), а я долбаеб - разные запросы даже по одному ресурсу выполняются в разных потоках, просто я обращался к одному ресурсу из двух вкладок одного клиента (гугл хром) и ASP.NET Core расценивал это, судя по всему, как один запрос, а если сделать это из разных клиентов (к примеру, хром, эдж и курл), то к ASP.NET Core пойдут, как и планировалось, 3 запроса и он раскидает их по 3 потокам
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
                    return;// Из-за этих моих пустых return'ов после await'ов мои компоненты middleware не смогут "встроиться" в конвейер, однако пока это неважно, т. к. дописать к return'ам вызовы делегатов следующих компонентов можно легко и в любой момент. Зато теперь мои компоненты имеют полноценные точки выхода (раньше они всегда "доходили" до закрывающей фигурной скобки, т. к. await'ы, оказывается, не заканчивают метод)
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

            string SimpleSending() => "Skala.png";// Браузеры не скачивают такие файлы, а просто открывают их во вкладке (для скачивания надо поменять один хедер (по аналогии, как и для отправки HTML-файлов нужен "ContentType: text/html"))

            await context.Response.SendFileAsync(DownloadFile());
            return;
        }
        public static async Task HttpContextMiddleware(HttpContext context)// Метод Run() помещает в конец конвейера делегат RequestDelegate, позволяющий благодаря своему параметру узнавать запрос и управлять ответом
        {
            void ResponseHeaders()// Поиграемся с заголовками ответа. Вообще эти хедеры просто подсказывают клиентам че делать с полученным ответом
            {
                HttpResponse response = context.Response;
                response.Headers.ContentLanguage = "ru-RU";
                response.Headers.ContentType = "text/plain; charset=utf-8";
                response.Headers.Append("secret-id", "256");// Добавление кастомного хедера
                response.StatusCode = 404;// Управление кодом статуса
                //response.ContentType = "text/html; charset=utf-8";// Что нужно для Html
                //response.Headers.ContentLength = 106;// Если значение этого заголовка будет меньше кол-ва передаваемых в теле ответа символов, то произойдет ошибка на стороне сервера ASP.NET Core и приложение упадет. По умолчанию этот заголовок отсутствует и вместо него стоит "Transfer-Encoding: chunked", обеспечивающий передачу сколь угодно больших динамических тел (но HTTP/2 не использует ни то, ни другое, а справляется как-то сам)
            }
            string RequestHeaders()// Получаем все заголовки запроса
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
            string RequestMyHeader()// Попытка получения кастомного хедера запроса
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
            //await context.Response.WriteAsync(context.Request.Path);// Записываем в тело ответа. Свойство "context.Request.Path" возвращает полный путь к запрашиваемому ресурсу (очевидно, что уже при помощи только этого можно замутить свою маршрутизацию)
        }
    }
}