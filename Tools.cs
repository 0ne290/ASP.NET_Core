namespace ASP.NET_Core_7
{
    public static class Tools
    {
        public delegate bool Comparison(int id, int num);
        public static string StringRandom(int length)
        {
            Random randomizer = new Random();
            char[] letters = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz".ToCharArray();
            char[] res = new char[length];
            for (int i = 0; i < length; i++)
                res[i] = letters[randomizer.Next(52)];
            return new string(res);
        }
        public static User[] UserRandom(int length)// Метод формирования массива случайных записей
        {
            Random randomizer = new Random();
            User[] res = new User[length];
            for (int i = 0; i < length; i++)
            {
                res[i] = new User();
                res[i].Age = randomizer.Next(100);
                res[i].Name = StringRandom(10);
            }
            return res;
        }
        public static int IntRandom(int lowerRange, int upperRange)
        {
            Random randomizer = new Random();
            return randomizer.Next(lowerRange, upperRange);
        }
        public static List<Person> GetPerson(this List<Person> list, int id, int age, Comparison operationId, Comparison operationAge)
        {
            List<Person> result = new List<Person>(20);
            foreach (Person person in list)
            {
                if (operationId(id, person.Id) && operationAge(age, person.Age))
                    result.Add(new Person(person));
            }
            return result;
        }
        public static bool Equals(int id, int num) => num == id;
        public static bool More(int id, int num) => num > id;
        public static bool Less(int id, int num) => num < id;
        public static bool Nothing(int id, int num) => true;
    }
}
