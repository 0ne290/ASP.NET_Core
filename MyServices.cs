namespace ASP.NET_Core_7
{
    public interface IMyService
    {
        public void Job(string message);
    }
    public class MyServiceOne : IMyService
    {
        public MyServiceOne() => Console.WriteLine("MyServiceOne construct work!");
        public void Job(string message) => Console.WriteLine($"=== ABOBA === {message} === ABOBA ===");
    }
    public class MyServiceTwo : IMyService
    {
        public MyServiceTwo() => Console.WriteLine("MyServiceTwo construct work!");
        public void Job(string message) => Console.WriteLine($"!!! 4UP4UJUHKA !!! {message} !!! 4UP4UJUHKA !!!");
    }
    public class MyServicesContainer
    {
        IMyService myService;
        public string Text { get; set; }
        public MyServicesContainer(IMyService myService)// В конструкторы сервисов невозможно передать параметры
        {
            Text = "StandartMessage";
            Console.WriteLine("MyServicesContainer construct work!");
            this.myService = myService;
        }
        public void Print() => myService.Job(Text);
    }
}
