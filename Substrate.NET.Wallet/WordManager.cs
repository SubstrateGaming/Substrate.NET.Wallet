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

        public ShouldManager Should()
        {
            return should;
        }

        public ShouldNotManager ShouldNot()
        {
            return shouldNot;
        }

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

        public bool IsValid(string password) => !GetErrors(password).Any();

        /// <summary>
        /// Get account name default policy
        /// </summary>
        /// <returns></returns>
        public static WordManager StandardAccountName =>
            WordManager.Create()
            .WithMinimumLength(4)
            .WithMaximumLength(20)
            .Should().AtLeastOneLowercase();

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

        public abstract class ShouldAbstract
        {
            protected WordManager wm;

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

                return errors;
            }
        }

        public class ShouldManager : ShouldAbstract
        {
            public ShouldManager(WordManager wm) : base(wm)
            {
            }

            public WordManager AtLeastOneUppercase()
            {
                uppercase = 1;
                return wm;
            }

            public WordManager AtLeastOneLowercase()
            {
                lowercase = 1;
                return wm;
            }

            public WordManager AtLeastOneDigit()
            {
                digit = 1;
                return wm;
            }
        }

        public class ShouldNotManager : ShouldManager
        {
            public ShouldNotManager(WordManager wm) : base(wm)
            {
            }

            public WordManager HaveUppercase()
            {
                uppercase = 0;
                return wm;
            }

            public WordManager HaveLowercase()
            {
                lowercase = 0;
                return wm;
            }

            public WordManager HaveDigit()
            {
                digit = 0;
                return wm;
            }
        }
    }
}