export class FeedEmpty extends HTMLElement {
  connectedCallback() {
    this.innerHTML = `<main id="main"><h1>Feed</h1>
      <p>No content yet &mdash; uploading arrives in a later phase.</p></main>`;
  }
}
customElements.define("feed-empty", FeedEmpty);
