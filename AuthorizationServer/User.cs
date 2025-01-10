namespace AuthorizationServer
{
    public class User
    {
        public string UserId { get; set; }
        public string Username { get; set; }

        public string Password { get; set; }

        public string Client { get; set; }

        public User(string id, string username, string password, string client)
        {
            UserId = id;
            Username = username;
            Password = password;
            Client = client;
        }

        public User()
        {
        }
    }
}