/** Allow importing .css files as side-effect modules. */
declare module "*.css" {
  const content: Record<string, string>;
  export default content;
}
