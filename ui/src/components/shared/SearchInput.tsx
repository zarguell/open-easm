import { type FC, type InputHTMLAttributes } from 'react'
import { Search } from 'lucide-react'

interface SearchInputProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'type'> {
  onSearch?: (value: string) => void
}

export const SearchInput: FC<SearchInputProps> = ({ onSearch, className = '', ...props }) => (
  <div className={`relative ${className}`}>
    <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-mute" />
    <input
      type="text"
      className="w-full rounded-md border border-hairline bg-canvas-soft py-3 pl-10 pr-4 text-sm text-ink placeholder:text-mute focus:outline-none focus:ring-1 focus:ring-primary"
      placeholder="Search entities..."
      onChange={(e) => onSearch?.(e.target.value)}
      {...props}
    />
  </div>
)
