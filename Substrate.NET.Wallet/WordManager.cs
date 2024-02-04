using System;
using System.Collections.Generic;
using System.Linq;

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

        private readonly ShouldManager should;
        private readonly ShouldNotManager shouldNot;

        /// <summary>
        /// Word manager constructor
        /// </summary>
        private WordManager()
        {
            should = new ShouldManager(this);
            shouldNot = new ShouldNotManager(this);
        }

        /// <summary>
        /// Create a new password manager
        /// </summary>
        /// <returns></returns>
        public static WordManager Create()
        {
            return new WordManager();
        }

        /// <summary>
        /// With minimum length
        /// </summary>
        /// <param name="length"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentException"></exception>
        public WordManager WithMinimumLength(int length)
        {
            if (length > maximumLength) throw new ArgumentException($"Minimum length ({length}) is greater than maximum length ({maximumLength})");

            minimumLength = length;
            return this;
        }

        /// <summary>
        /// With maximum length
        /// </summary>
        /// <param name="length"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentException"></exception>
        public WordManager WithMaximumLength(int length)
        {
            if (length < minimumLength) throw new ArgumentException($"Maximum length ({length}) is lower than minimum length ({minimumLength})");

            maximumLength = length;
            return this;
        }

        /// <summary>
        /// Should
        /// </summary>
        /// <returns></returns>
        public ShouldManager Should()
        {
            return should;
        }

        /// <summary>
        /// Should not
        /// </summary>
        /// <returns></returns>
        public ShouldNotManager ShouldNot()
        {
            return shouldNot;
        }

        /// <summary>
        /// Get errors
        /// </summary>
        /// <param name="word"></param>
        /// <returns></returns>
        public IEnumerable<string> GetErrors(string word)
        {
            var errors = new List<string>();
            if (word.Length < minimumLength)
                errors.Add($"Length should be at least {minimumLength} caracters");

            if (word.Length > maximumLength)
                errors.Add($"Length should be maximum {maximumLength} caracters");

            errors.AddRange(should.GetErrors(word));
            errors.AddRange(shouldNot.GetErrors(word));

            return errors;
        }

        /// <summary>
        /// Is valid password
        /// </summary>
        /// <param name="password"></param>
        /// <returns></returns>
        public bool IsValid(string password) => !GetErrors(password).Any();

        /// <summary>
        /// Get account name default policy
        /// </summary>
        /// <returns></returns>
        public static WordManager StandardAccountName =>
            WordManager.Create()
            .WithMinimumLength(4)
            .WithMaximumLength(20)
            .Should().AtLeastOneLetter();

        /// <summary>
        /// Get password default policy
        /// </summary>
        /// <returns></returns>
        public static WordManager StandardPassword =>
            WordManager.Create()
            .WithMinimumLength(4).WithMaximumLength(20)
            .Should().AtLeastOneDigit()
            .Should().AtLeastOneLowercase()
            .Should().AtLeastOneUppercase();

        /// <summary>
        /// Should abstract
        /// </summary>
        public abstract class ShouldAbstract
        {
            protected WordManager wm;

            /// <summary>
            /// Should abstract constructor
            /// </summary>
            /// <param name="wm"></param>
            protected ShouldAbstract(WordManager wm)
            {
                this.wm = wm;
            }

            /// <summary>
            /// Upercase letter requirement
            /// </summary>
            protected int? uppercase = null;

            /// <summary>
            /// Lowercase letter requirement
            /// </summary>
            protected int? lowercase = null;

            /// <summary>
            /// Digit letter requirement
            /// </summary>
            protected int? digit = null;

            /// <summary>
            /// Alphanumeric latter requirement
            /// </summary>
            protected int? letter = null;

            /// <summary>
            /// Get errors
            /// </summary>
            /// <param name="word"></param>
            /// <returns></returns>
            public IEnumerable<string> GetErrors(string word)
            {
                var errors = new List<string>();

                var hasUpper = word.Any(char.IsUpper);
                if (hasUpper && uppercase != null && uppercase.Value == 0)
                    errors.Add($"Uppercase letter forbiden");

                if (!hasUpper && uppercase != null && uppercase.Value > 0)
                    errors.Add($"Uppercase letter required");

                var hasLower = word.Any(char.IsLower);
                if (hasLower && lowercase != null && lowercase.Value == 0)
                    errors.Add($"Lowercase letter forbiden");

                if (!hasLower && lowercase != null && lowercase.Value > 0)
                    errors.Add($"Lowercase letter required");

                var hasDigit = word.Any(char.IsDigit);
                if (hasDigit && digit != null && digit.Value == 0)
                    errors.Add($"Digit forbiden");

                if (!hasDigit && digit != null && digit.Value > 0)
                    errors.Add($"Digit required");

                var hasLetter = word.Any(char.IsLetter);
                if (hasLetter && letter != null && letter.Value == 0)
                    errors.Add($"Letter forbiden");

                if (!hasLetter && letter != null && letter.Value > 0)
                    errors.Add($"Latter required");

                return errors;
            }
        }

        /// <summary>
        /// Should manager
        /// </summary>
        public class ShouldManager : ShouldAbstract
        {
            /// <summary>
            /// Should manager constructor
            /// </summary>
            /// <param name="wm"></param>
            public ShouldManager(WordManager wm) : base(wm)
            {
            }

            /// <summary>
            /// At least one uppercase letter
            /// </summary>
            /// <returns></returns>
            public WordManager AtLeastOneUppercase()
            {
                uppercase = 1;
                return wm;
            }

            /// <summary>
            /// At least one lowercase letter
            /// </summary>
            /// <returns></returns>
            public WordManager AtLeastOneLowercase()
            {
                lowercase = 1;
                return wm;
            }

            /// <summary>
            /// At least one digit
            /// </summary>
            /// <returns></returns>
            public WordManager AtLeastOneDigit()
            {
                digit = 1;
                return wm;
            }

            /// <summary>
            /// At least one digit
            /// </summary>
            /// <returns></returns>
            public WordManager AtLeastOneLetter()
            {
                letter = 1;
                return wm;
            }
        }

        /// <summary>
        /// Should not manager
        /// </summary>
        public class ShouldNotManager : ShouldManager
        {
            /// <summary>
            /// Should not manager constructor
            /// </summary>
            /// <param name="wm"></param>
            public ShouldNotManager(WordManager wm) : base(wm)
            {
            }

            /// <summary>
            /// Have uppercase letter
            /// </summary>
            /// <returns></returns>
            public WordManager HaveUppercase()
            {
                uppercase = 0;
                return wm;
            }

            /// <summary>
            /// Have lowercase letter
            /// </summary>
            /// <returns></returns>
            public WordManager HaveLowercase()
            {
                lowercase = 0;
                return wm;
            }

            /// <summary>
            /// Have digit
            /// </summary>
            /// <returns></returns>
            public WordManager HaveDigit()
            {
                digit = 0;
                return wm;
            }

            /// <summary>
            /// Have letter
            /// </summary>
            /// <returns></returns>
            public WordManager HaveLetter()
            {
                letter = 0;
                return wm;
            }
        }
    }
}