/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './templates/**/*.html',
    // Jail ごとの色クラス（bg-blue-500 など）は app.py の JAIL_COLORS で定義され
    // API 経由でフロントに渡されるため、走査対象に含めないと CSS から漏れる
    './backend/app.py',
  ],
  theme: {
    extend: {},
  },
  plugins: [],
};
