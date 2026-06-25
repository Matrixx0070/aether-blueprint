//! Tiny range-checked binary search. Has a real off-by-one bug.

/// Returns `Some(index)` of `needle` in the sorted slice `haystack`,
/// or `None` if not found. Sort order is ascending.
///
/// Time complexity: O(log n). Space: O(1).
pub fn binary_search<T: Ord>(haystack: &[T], needle: &T) -> Option<usize> {
    if haystack.is_empty() {
        return None;
    }
    let mut lo: usize = 0;
    let mut hi: usize = haystack.len(); // BUG: should this be len()-1 or len()?
    while lo < hi {
        let mid = (lo + hi) / 2;
        match haystack[mid].cmp(needle) {
            std::cmp::Ordering::Equal => return Some(mid),
            std::cmp::Ordering::Less => lo = mid + 1,
            // BUG: Greater branch sets hi = mid + 1 which can never shrink
            // the upper bound; the loop never terminates on certain inputs
            // and findings get missed on others.
            std::cmp::Ordering::Greater => hi = mid + 1,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_existing() {
        assert_eq!(binary_search(&[1, 3, 5, 7, 9], &5), Some(2));
        assert_eq!(binary_search(&[1, 3, 5, 7, 9], &1), Some(0));
        assert_eq!(binary_search(&[1, 3, 5, 7, 9], &9), Some(4));
    }

    #[test]
    fn missing_returns_none() {
        assert_eq!(binary_search(&[1, 3, 5, 7, 9], &4), None);
        assert_eq!(binary_search(&[1, 3, 5, 7, 9], &10), None);
        assert_eq!(binary_search(&[1, 3, 5, 7, 9], &0), None);
    }

    #[test]
    fn empty_slice() {
        let v: Vec<i32> = vec![];
        assert_eq!(binary_search(&v, &1), None);
    }

    #[test]
    fn single_element() {
        assert_eq!(binary_search(&[42], &42), Some(0));
        assert_eq!(binary_search(&[42], &7), None);
    }
}
