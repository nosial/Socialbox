package net.nosial.socialbox.objects;

import java.util.List;
import java.util.function.ToLongFunction;

public record CursorPage<T>(List<T> items, long cursor, boolean more, boolean reset)
{
    /**
     * Builds a page from rows fetched with one row more than the page size, which tells whether more follow.
     *
     * @param rows The rows, up to {@code size + 1}, oldest first.
     * @param after The requested cursor.
     * @param size The page size.
     * @param position The position (cursor value) of an item.
     * @param <T> The item type.
     * @return The page.
     */
    public static <T> CursorPage<T> of(List<T> rows, long after, int size, ToLongFunction<T> position)
    {
        boolean more = rows.size() > size;
        List<T> items = List.copyOf(more ? rows.subList(0, size) : rows);
        return new CursorPage<>(items, items.isEmpty() ? after : position.applyAsLong(items.getLast()), more, false);
    }
}
