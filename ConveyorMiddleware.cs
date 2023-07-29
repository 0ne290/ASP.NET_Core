namespace ASP.NET_Core_7
{
    public static class ConveyorMiddleware// ASP.NET Core сам автоматически будет присваивать context и next при получении запроса (т. к. эти компоненты вызываются, опять же, самим ASP.NET Core). Значение второго параметра представляет собой делегат следующего компонента в конвейере, который настраивается с помощью специальных методов класса WebApplication
    {
        //public static async Task FirstComponentNonDelegate(HttpContext context, Func<Task> next)// Это неведомое мне Func<Task> не совсем понятно
        //{
        //
        //}
        public static async Task FirstComponentDelegate(HttpContext context, RequestDelegate next)// Так что пока лучше через делегат
        {
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine("First component work before second!");
            next.Invoke(context);
            Console.WriteLine("First component work after second!");
            return;
        }
        public static async Task SecondComponentDelegate(HttpContext context, RequestDelegate next)// Так что пока лучше через делегат
        {
            Console.WriteLine("Second component work before third and after first!");
            next.Invoke(context);
            Console.WriteLine("Second component work after third and after-after first!");
            return;
        }
        public static async Task ThirdComponentDelegate(HttpContext context, RequestDelegate next)// Так что пока лучше через делегат
        {
            Console.WriteLine("Third component work before fourth and after second!");
            next.Invoke(context);
            Console.WriteLine("Third component work after fourth and after-after second!");
            return;
        }
        public static async Task LastComponentDelegate(HttpContext context)// Так что пока лучше через делегат
        {
            Console.WriteLine("Last component worked and now the conveyor went in the opposite direction!");
            return;
        }
    }
}
