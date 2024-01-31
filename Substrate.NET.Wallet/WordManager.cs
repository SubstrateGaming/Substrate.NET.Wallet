using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Substrate.NET.Wallet
{
    /// <summary>
    /// Build rules on a phrase
    /// </summary>
    public class WordManager
    {
        /// <summary>
        /// Minimum of character
        /// </summary>
        private int minimumLength = default;

        /// <summary>
        /// Maximum of character
        /// </summary>
        private int maximumLength = int.MaxValue;

        /// <summary>
        /// Upercase letter requirement
        /// </summary>
        private bool requireUppercase = false;

        /// <summary>
        /// Lowercase letter requirement
        /// </summary>
        private bool requireLowercase = false;

        /// <summary>
        /// Digit letter requirement
        /// </summary>
        private bool requireDigit = false;

        /// <summary>
        /// Create a new password manager
        /// </summary>
        /// <returns></returns>
        public static WordManager Create()
        {
            return new WordManager();
        }

        /// <summary>
        /// Get default value
        /// </summary>
        /// <returns></returns>
        public static WordManager StandardRequirement() => 
            WordManager.Create()
            .WithMinimumLength(4)
            .WithMaximumLength(20)
            .WithAtLeastOneUppercase()
            .WithAtLeastOneLowercase()
            .WithAtLeastOneDigit();

        public WordManager WithMinimumLength(int length)
        {
            if (length > maximumLength) throw new ArgumentException($"Minimum length ({length}) is greater than maximum length ({maximumLength})");

            minimumLength = length;
            return this;
        }

        public WordManager WithMaximumLength(int length)
        {
            if (length < minimumLength) throw new ArgumentException($"Maximum length ({length}) is lower than minimum length ({minimumLength})");

            maximumLength = length;
            return this;
        }

        public WordManager WithAtLeastOneUppercase()
        {
            requireUppercase = true;
            return this;
        }

        public WordManager WithAtLeastOneLowercase()
        {
            requireLowercase = true;
            return this;
        }

        public WordManager WithAtLeastOneDigit()
        {
            requireDigit = true;
            return this;
        }

        

        public IEnumerable<string> GetErrors(string password)
        {
            var errors = new List<string>();
            if (password.Length < minimumLength)
                errors.Add($"Length should be at least {minimumLength} caracters");

            if (password.Length > maximumLength)
                errors.Add($"Length should be maximum {maximumLength} caracters");

            if (requireUppercase && !password.Any(char.IsUpper))
                errors.Add($"Uppercase letter required");

            if (requireLowercase && !password.Any(char.IsLower))
                errors.Add($"Lowercase letter required");

            if (requireDigit && !password.Any(char.IsDigit))
                errors.Add($"Digit required");

            return errors;
        }

        public bool IsValid(string password) => !GetErrors(password).Any();
    }
}
