namespace ASP.NET_Core_7
{
    public class MultipleRegistrationMiddleware
    {
        RequestDelegate next;

        public MultipleRegistrationMiddleware(RequestDelegate pNext)
        {
            next = pNext;
        }

        public async Task InvokeAsync(HttpContext context, IEnumerable<IMyService> myServices)
        {
            foreach (IMyService service in myServices)
            {
                service.Job("Multiple registration");
            }
            await next.Invoke(context);
            return;
        }
    }
}
