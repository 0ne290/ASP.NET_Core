namespace ASP.NET_Core_7
{
    public class TokenMiddleware
    {
        private readonly RequestDelegate next;// Системное поле - делегат следующего компонента
        private string _token;// Пользовательское поле

        public TokenMiddleware(RequestDelegate next, string token)// Пользовательские поля могут настраиваться только через конструктор в момент добавления компонента
        {
            this.next = next;
            _token = token;
        }

        public async Task InvokeAsync(HttpContext context)// Сигнатура метода работы компонента и перехода (очевидно, опционального) к следующему компоненту должна быть именно такой. Иначе - ошибка
        {
            string token = context.Request.Query["token"];
            if (token != _token)
            {
                context.Response.StatusCode = 403;
                await context.Response.WriteAsync("Token is invalid");
            }
            else
            {
                await next.Invoke(context);
            }
        }
    }
}
