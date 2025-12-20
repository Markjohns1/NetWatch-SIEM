/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                background: "#0a0b14",
                foreground: "#ffffff",
                primary: {
                    DEFAULT: "#00f2ff",
                    foreground: "#0a0b14",
                },
                secondary: {
                    DEFAULT: "#7000ff",
                    foreground: "#ffffff",
                },
                accent: {
                    DEFAULT: "#ff0055",
                    foreground: "#ffffff",
                },
                muted: "#1e1f2e",
                border: "#2e2f3e",
            },
            backgroundImage: {
                'cyber-gradient': 'linear-gradient(135deg, #0a0b14 0%, #1e1f2e 100%)',
                'neon-glow': 'radial-gradient(circle, rgba(0, 242, 255, 0.1) 0%, transparent 70%)',
            },
        },
    },
    plugins: [],
}
