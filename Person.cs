namespace ASP.NET_Core_7
{
    public class Person
    {
        private static int id = 0;

        private int _id, _age;
        public int Id
        {
            get
            {
                return _id;
            }
        }
        public int Age
        {
            get
            {
                return _age;
            }
        }
        private string _name;
        public string Name
        {
            get
            {
                return new string(_name);
            }
        }

        public Person(string name, int age)
        {
            if ((name?.Length ?? 0) < 10)
                _name = Tools.StringRandom(10);
            else
                _name = new string(name);
            _age = age < 0 ? Tools.IntRandom(0, 70) : age;
            _id = id;
            id++;
        }
        public Person(Person person)
        {
            _name = person.Name;
            _age = person.Age;
            _id = person.Id;
        }
    }
}
