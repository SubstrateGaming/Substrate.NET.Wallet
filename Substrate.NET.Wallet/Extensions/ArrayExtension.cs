using System;

namespace Substrate.NET.Wallet.Extensions
{
    public static class ArrayExtension
    {
        /// <summary>
        /// Read an array from start index to end index
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="array"></param>
        /// <param name="start"></param>
        /// <param name="end"></param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        public static T[] SubArray<T>(this T[] array, int start, int end)
        {
            if (array == null)
                throw new ArgumentNullException(nameof(array));

            if (start < 0 || start >= array.Length)
                throw new ArgumentOutOfRangeException(nameof(start), "Start index is out of bounds.");

            if (end < start || end > array.Length)
                throw new ArgumentOutOfRangeException(nameof(end), "End index is out of bounds or less than start index.");

            int length = end - start;

            T[] result = new T[length];
            Array.Copy(array, start, result, 0, length);
            return result;
        }

        public static T[] SubArray<T>(this T[] array, int start) => array.SubArray(start, array.Length);
    }
}