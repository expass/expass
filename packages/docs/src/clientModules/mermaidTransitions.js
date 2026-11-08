// Mermaid's tooltips call selection.transition(). Load the D3 module explicitly
// so bundlers retain the side effect that registers it on selection.prototype.
import 'd3-transition';
