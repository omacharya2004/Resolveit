# ResolveIt Logo Usage Guide

## Overview
The ResolveIt complaint management system features a professional, theme-aware logo design that automatically adapts to both light and dark modes for optimal visibility and user experience.

## Logo Files

### 1. `static/logo-icon.svg` (40x40px)
- **Usage**: Navigation bar, small UI elements
- **Features**: Compact circular design with checkmark and success dots
- **Theme Support**: Automatically switches colors based on current theme

### 2. `static/logo.svg` (200x60px)
- **Usage**: About page, medium-sized displays
- **Features**: Full logo with text and subtitle
- **Theme Support**: Complete theme adaptation for all elements

### 3. `static/logo-horizontal.svg` (300x80px)
- **Usage**: Headers, large displays, marketing materials
- **Features**: Extended horizontal layout with full branding
- **Theme Support**: Professional presentation in both themes

### 4. `static/favicon.svg` (32x32px)
- **Usage**: Browser tabs, bookmarks
- **Features**: Simplified version for small displays
- **Theme Support**: Optimized for browser context

## Design Elements

### Color Scheme
- **Light Mode Primary**: `#667eea` (Purple-Blue gradient)
- **Dark Mode Primary**: `#3b82f6` (Blue)
- **Success Color**: `#10b981` (Green - consistent across themes)
- **Text Colors**: Automatically adapt to theme contrast

### Visual Elements
1. **Circular Background**: Represents completeness and professionalism
2. **Checkmark**: Symbolizes resolution and success
3. **Success Dots**: Indicate resolved issues and positive outcomes
4. **Modern Typography**: Clean, professional font styling

## Theme Integration

### Light Mode
- Primary colors use the application's purple-blue gradient
- Text uses standard dark colors for contrast
- Subtle shadows and effects for depth

### Dark Mode
- Primary colors switch to blue tones for better dark theme integration
- Text colors adapt to light colors for proper contrast
- Enhanced shadows and effects for visibility

## CSS Classes

### Logo Styling Classes
- `.navbar-logo`: Navigation bar logo styling
- `.login-logo`: Login page logo with enhanced visibility
- `.about-logo`: About page logo with subtle styling
- `.logo-loading`: Animation class for loading states

### Automatic Theme Detection
The logos automatically detect the current theme using CSS custom properties:
```css
svg .logo-circle {
    fill: var(--primary-color);
}
body.dark-mode svg .logo-circle {
    fill: var(--dark-accent);
}
```

## Usage Examples

### Navigation Bar
```html
<img src="{{ url_for('static', filename='logo-icon.svg') }}" 
     alt="ResolveIt Logo" 
     width="32" height="32" 
     class="navbar-logo">
```

### Login Page
```html
<img src="{{ url_for('static', filename='logo-icon.svg') }}" 
     alt="ResolveIt Logo" 
     width="80" height="80" 
     class="login-logo">
```

### About Page
```html
<img src="{{ url_for('static', filename='logo.svg') }}" 
     alt="ResolveIt Logo" 
     width="200" height="60" 
     class="about-logo">
```

## Best Practices

1. **Always use SVG format** for scalability and theme support
2. **Include appropriate alt text** for accessibility
3. **Use semantic class names** for consistent styling
4. **Test in both themes** to ensure proper visibility
5. **Maintain aspect ratios** when resizing

## Accessibility

- All logos include proper alt text
- High contrast ratios in both light and dark modes
- Scalable vector format for screen readers
- Consistent color schemes for colorblind users

## Browser Support

- Modern browsers with SVG support
- CSS custom properties support
- Graceful degradation for older browsers

## Maintenance

- Logo colors automatically sync with theme changes
- CSS custom properties ensure easy color updates
- SVG format allows for easy modifications
- Consistent styling across all logo instances
