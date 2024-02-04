using Serilog;
using System;
using System.Text.Json;

namespace Substrate.NET.Wallet
{
    /// <summary>
    /// Caching
    /// </summary>
    public static class Caching
    {
        /// <summary> The logger. </summary>
        private static readonly ILogger Logger = new LoggerConfiguration().CreateLogger();

        /// <summary>
        /// Tries the read file.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="path">The path.</param>
        /// <param name="obj">The object.</param>
        /// <returns></returns>
        public static bool TryReadFile<T>(string path, out T obj)
        {
            obj = default;

            try
            {
                var objDecrypted = Decrypt(SystemInteraction.ReadAllText(path));
                obj = JsonSerializer.Deserialize<T>(objDecrypted);
                return true;
            }
            catch (Exception e)
            {
                Logger.Error($"TryReadFile<{obj?.GetType()}>: {e}");
                return false;
            }
        }

        /// <summary>
        /// Persists the specified path.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="path">The path.</param>
        /// <param name="obj">The object.</param>
        public static void Persist<T>(string path, T obj)
        {
            var objEncrypted = Encrypt(JsonSerializer.Serialize(obj));
            SystemInteraction.Persist(path, objEncrypted);
        }

        //unused, already encrypted maybe for later
        private static string Encrypt(string str)
        {
            return str;
        }

        //unused, already encrypted maybe for later
        private static string Decrypt(string str)
        {
            return str;
        }
    }
}