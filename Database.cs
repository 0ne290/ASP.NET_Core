using System.Collections.Generic;
using System.Diagnostics;
using Microsoft.EntityFrameworkCore;

namespace ASP.NET_Core_7
{
    public class DatabaseBegin
    {
        //public static object locker = new object();// 111111
        //public static int start = 4;// 222222
        private readonly RequestDelegate next;
        public DatabaseBegin(RequestDelegate next)
        {
            this.next = next;
        }
        public async Task InvokeAsync(HttpContext context, MyDbContext db)// Версия для Scoped
        {
            //lock (locker) 111111
            //{
            //    Console.WriteLine(Thread.CurrentThread.ManagedThreadId);
            //}
            //Thread.Sleep(1000);

            //var sw = new Stopwatch(); 222222
            //Interlocked.Decrement(ref start);
            //while (start != 0)// Если threads равен 0, то это значит, что все потоки работы с БД завершили свою основную работу (но это не значит, что они окончательно завершены - в данном случае, если threads равен 0, то все методы Create() подготовили свои SQL-команды, но еще не инъецировали их в БД и не закомитили ее (методы SaveChanges() и Dispose(), соответственно))
            //    Thread.Sleep(0);
            //sw.Start();

            await next.Invoke(context);
            db.Dispose();

            //sw.Stop(); 222222
            //Interlocked.Increment(ref start);
            //lock (locker)
            //{
            //    Console.WriteLine(sw.ElapsedTicks);
            //}
        }
    }
    public class User
    {
        public int Id { get; set; }
        public string? Name { get; set; }
        public int Age { get; set; }
    }
    public class MyDbContext : DbContext// Т. к. классическое использование баз данных в ASP.NET Core налажено через сервисы, то использование конструкторов нежелательно (более того: бессмысленно и вообще вредительство). Почему? А потому что в конструктор ты не передашь никаких параметров, кроме зависимостей (других сервисов). Также можно отказаться и от метода OnConfiguring, т. к. у метода AddDbContext<>(), добавляющего БД в сервисы, есть параметр Action<DbContextOptionsBuilder>, позволяющий манипулировать DbContextOptionsBuilder создаваемого контекста БД также, как и метод OnConfiguring
    {
        public DbSet<User> Users { get; set; } = null!;
        public MyDbContext(DbContextOptions<MyDbContext> options) : base(options) { }
        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            optionsBuilder.UseSqlite("Data Source=helloapp.db");
        }
    }
}
