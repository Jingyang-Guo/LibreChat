export function getMessageRowWidthClass({
  fullWidth = false,
  hasParallelContent = false,
}: {
  fullWidth?: boolean;
  hasParallelContent?: boolean;
} = {}): string {
  if (fullWidth) return 'w-full max-w-full sm:px-2';
  if (hasParallelContent) return 'w-full sm:px-2 md:max-w-3xl xl:max-w-3xl';
  return 'w-full sm:px-2 md:max-w-3xl xl:max-w-3xl';
}
