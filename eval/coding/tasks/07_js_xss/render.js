// Renders a user comment to an HTML string. This is server-rendered
// (Node) HTML that gets inserted into a page via .innerHTML.
//
// CURRENT IMPLEMENTATION has an XSS hole: it interpolates raw user
// input directly into the HTML.

function renderComment(comment) {
    return `<div class="comment">
        <span class="author">${comment.author}</span>
        <p class="body">${comment.body}</p>
    </div>`;
}

module.exports = { renderComment };
