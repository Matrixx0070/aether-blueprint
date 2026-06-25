import java.util.HashMap;
import java.util.Map;

// A tiny stock-keeping helper. The current implementation throws a
// NullPointerException when the SKU isn't in the inventory map.
public class Inventory {
    private final Map<String, Integer> stock = new HashMap<>();

    public void restock(String sku, int qty) {
        Integer current = stock.get(sku);
        stock.put(sku, current + qty);  // BUG: NPE when sku is new (current == null)
    }

    public int available(String sku) {
        // BUG: also NPE when not present
        return stock.get(sku).intValue();
    }

    public boolean canFulfill(String sku, int qty) {
        return available(sku) >= qty;  // BUG: NPE chain via available()
    }
}
