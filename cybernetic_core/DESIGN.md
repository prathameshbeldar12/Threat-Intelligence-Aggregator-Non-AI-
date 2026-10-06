---
name: Cybernetic Core
colors:
  surface: '#121318'
  surface-dim: '#121318'
  surface-bright: '#38393f'
  surface-container-lowest: '#0d0e13'
  surface-container-low: '#1a1b21'
  surface-container: '#1e1f25'
  surface-container-high: '#292a2f'
  surface-container-highest: '#34343a'
  on-surface: '#e3e1e9'
  on-surface-variant: '#b9cacb'
  inverse-surface: '#e3e1e9'
  inverse-on-surface: '#2f3036'
  outline: '#849495'
  outline-variant: '#3a494b'
  surface-tint: '#00dbe7'
  primary: '#e1fdff'
  on-primary: '#00363a'
  primary-container: '#00f2ff'
  on-primary-container: '#006a71'
  inverse-primary: '#00696f'
  secondary: '#adc6ff'
  on-secondary: '#002e6a'
  secondary-container: '#0566d9'
  on-secondary-container: '#e6ecff'
  tertiary: '#fcf5ff'
  on-tertiary: '#3c0091'
  tertiary-container: '#e2d4ff'
  on-tertiary-container: '#6f3cd8'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#74f5ff'
  primary-fixed-dim: '#00dbe7'
  on-primary-fixed: '#002022'
  on-primary-fixed-variant: '#004f54'
  secondary-fixed: '#d8e2ff'
  secondary-fixed-dim: '#adc6ff'
  on-secondary-fixed: '#001a42'
  on-secondary-fixed-variant: '#004395'
  tertiary-fixed: '#e9ddff'
  tertiary-fixed-dim: '#d0bcff'
  on-tertiary-fixed: '#23005c'
  on-tertiary-fixed-variant: '#5516be'
  background: '#121318'
  on-background: '#e3e1e9'
  surface-variant: '#34343a'
typography:
  display-lg:
    fontFamily: Inter
    fontSize: 48px
    fontWeight: '700'
    lineHeight: 56px
    letterSpacing: -0.02em
  headline-lg:
    fontFamily: Inter
    fontSize: 32px
    fontWeight: '600'
    lineHeight: 40px
    letterSpacing: -0.01em
  headline-md:
    fontFamily: Inter
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
  body-lg:
    fontFamily: Inter
    fontSize: 18px
    fontWeight: '400'
    lineHeight: 28px
  body-md:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
  body-sm:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  data-mono:
    fontFamily: JetBrains Mono
    fontSize: 14px
    fontWeight: '500'
    lineHeight: 20px
  label-caps:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '700'
    lineHeight: 16px
    letterSpacing: 0.05em
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  unit: 4px
  container-padding: 24px
  gutter: 16px
  stack-sm: 8px
  stack-md: 16px
  stack-lg: 32px
---

## Brand & Style

The design system is engineered for high-stakes Security Operations Centers where clarity, speed of cognition, and technical authority are paramount. The personality is "Sentinel Modern"—an aesthetic that feels advanced and vigilant without falling into over-stylized gaming tropes. 

The design style utilizes **Glassmorphism** and **Minimalism**. It relies on deep atmospheric layering to create a sense of infinite digital space, using translucency to maintain context while focusing on specific data streams. Surfaces are treated as semi-transparent lenses over a void, utilizing precise neon accents to draw attention to critical security anomalies and system states.

## Colors

The palette is anchored in a "Deep Space" hierarchy. The primary background is nearly pitch black to reduce eye strain during long shifts, while surfaces use a deep navy to provide structural definition.

- **Primary (Cyan):** Used for active states, primary actions, and "online" telemetry.
- **Accents (Blue/Purple):** Used for data visualization categories and secondary navigation.
- **Functional (Severity):** These follow industry standards but are calibrated for high vibrancy against dark backgrounds to ensure immediate detection of threats.
- **Glass Surfaces:** Use `#1e293b` at 40% opacity with a background blur of 12px-20px to create depth.

## Typography

This design system uses a dual-font approach. **Inter** provides high legibility for interface controls, prose, and headings. **JetBrains Mono** is reserved for technical data, IP addresses, logs, and status labels, reinforcing the "tooling" nature of the platform.

For mobile viewports, `display-lg` should scale down to 32px and `headline-lg` to 24px. Use the monospaced font for all numeric values in tables to ensure tabular alignment and rapid scanning.

## Layout & Spacing

The layout utilizes a **Fixed Grid** on desktop (12 columns) and a **Fluid Grid** on mobile. Given the information density of an SOC, the system prioritizes a "dashboard-first" layout with collapsible sidebars to maximize the central workspace.

- **Desktop:** 12 columns, 24px margins, 16px gutters.
- **Tablet:** 8 columns, 16px margins, 12px gutters.
- **Mobile:** 4 columns, 16px margins, 8px gutters.

The spacing rhythm is based on a 4px baseline, ensuring all components align to a mathematical grid for a clean, technical appearance.

## Elevation & Depth

Elevation is expressed through **Tonal Layers** and **Backdrop Blurs** rather than traditional drop shadows. 

1. **Level 0 (Base):** `#050507` — The void background.
2. **Level 1 (Sub-surface):** `#0a0b10` — Used for sidebar areas or grouped background sections.
3. **Level 2 (Glass Panel):** Semi-transparent `rgba(30, 41, 59, 0.4)` with 12px blur and a 1px border of `rgba(255, 255, 255, 0.1)`.
4. **Level 3 (Popovers/Modals):** Same as Level 2 but with a subtle outer glow using the primary cyan at 5% opacity to indicate focus.

Interaction triggers a "glow" rather than a "lift." When a user hovers over a glass card, the border opacity increases from 0.1 to 0.3.

## Shapes

The shape language is precise and "Soft" (0.25rem/4px). This subtle rounding prevents the UI from feeling aggressive or "brutalist" while maintaining the professional, structural integrity of enterprise software. 

- **Standard Elements:** 4px (Inputs, Buttons, Cards).
- **Interactive Badges:** 2px (Small tags, status indicators).
- **System Containers:** 8px (Large dashboard panels).

## Components

### Buttons
Primary buttons use a solid Cyan-to-Blue subtle gradient with black text for maximum contrast. Secondary buttons use the "Glass" style with a 1px border. All buttons have a high-active state where the border gains a subtle neon outer glow.

### Modern Data Tables
Tables are the heart of the design system. Use `data-mono` for all cell content. Row separators are 1px semi-transparent lines. Use "Zebra striping" with subtle opacity shifts (2%) instead of solid colors.

### Interactive Status Badges
Status badges use a "hollow" style: a 1px border of the severity color, a 10% opacity fill of the same color, and a small 4px solid dot next to the label.

### Input Fields
Inputs are dark with a bottom-only 1px border in the default state. Upon focus, the border transitions to the primary Cyan and expands to all four sides with a subtle inner glow.

### Glass-Effect Panels
Main dashboard widgets are housed in glass panels. Headers within these panels should have a subtle bottom border to separate controls from data.

### Additional Components
- **Node Graph:** For visualization of network threats, using thin primary-colored lines and glowing terminal nodes.
- **Timeline Scrubber:** A monospaced horizontal axis for scrubbing through security events.