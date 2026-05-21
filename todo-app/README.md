# 📝 To-Do List Application with Local Storage

A modern, feature-rich to-do list application with persistent local storage, built with vanilla JavaScript, HTML, and CSS.

## ✨ Features

### Core Functionality
- ✅ **Add Tasks** - Create new tasks with ease
- 🏷️ **Priority Levels** - Assign Low, Medium, or High priority to each task
- ✓ **Complete Tasks** - Mark tasks as done with visual feedback
- 🗑️ **Delete Tasks** - Remove individual tasks with confirmation
- 🔍 **Search** - Real-time search through your tasks
- 📊 **Filter Tasks** - Filter by status (All, Active, Completed) or priority

### Local Storage
- 💾 **Auto-Save** - Automatically saves every 10 seconds
- 🔄 **Persistent** - Data persists across browser sessions
- ⚡ **Instant Save** - Saves immediately on any change
- 🛡️ **Safe Unload** - Saves data when closing the page

### Statistics
- 📈 **Task Count** - View total, completed, and remaining tasks
- 🎯 **Progress Tracking** - Monitor your productivity

### User Experience
- 🎨 **Modern Design** - Beautiful gradient UI with smooth animations
- 📱 **Responsive** - Works perfectly on desktop, tablet, and mobile
- ⌨️ **Keyboard Support** - Full keyboard navigation
- 🎯 **Color Coded** - Priority badges with intuitive colors
- 🚀 **Smooth Animations** - Delightful transitions and effects

## 📁 File Structure

```
todo-app/
├── index.html       # HTML structure and markup
├── styles.css       # Complete styling with responsive design
├── app.js           # Application logic and local storage management
└── README.md        # This file
```

## 🚀 Quick Start

1. **Download** all three files to the same folder
2. **Open** `index.html` in your web browser
3. **Start using** - No installation or server needed!

### Browser Requirements
- Modern browser with ES6+ support
- Local Storage support (all modern browsers)
- JavaScript enabled

## 🎮 How to Use

### Adding a Task
1. Type your task in the input field
2. Choose a priority level (Low, Medium, High)
3. Click "Add Task" or press Enter

### Completing a Task
- Click the checkbox next to a task to mark it as complete
- Completed tasks appear grayed out with a strikethrough

### Deleting a Task
- Click the "Delete" button on any task
- Confirm the deletion when prompted

### Filtering Tasks
- Click filter buttons to view:
  - **All** - Show all tasks
  - **Active** - Show incomplete tasks only
  - **Completed** - Show completed tasks only
  - **High Priority** - Show only high-priority tasks

### Searching Tasks
- Type in the search box to filter tasks by text
- Search works in real-time as you type
- Works with all active filters

### Bulk Actions
- **Clear Completed** - Delete all completed tasks at once
- **Clear All** - Delete all tasks (with confirmation)

## 💾 Local Storage Details

### Data Structure
Each todo is stored as a JSON object with:
```javascript
{
  id: 1234567890,                    // Unique timestamp-based ID
  text: "Task description",           // Task text
  completed: false,                   // Completion status
  priority: "medium",                 // Priority: low, medium, high
  createdAt: "2024-01-01T...",       // Creation timestamp
  completedAt: null                   // Completion timestamp (if completed)
}
```

### Storage Key
- **Key**: `todos`
- **Location**: Browser's `localStorage`
- **Capacity**: ~5-10MB depending on browser

### Auto-Save Strategy
1. **Immediate Save**: Triggered on any action (add, delete, toggle)
2. **Periodic Save**: Every 10 seconds as backup
3. **Unload Save**: When closing/leaving the page
4. **Error Handling**: Gracefully handles storage quota exceeded

## 🎨 Customization

### Change Theme Colors
Edit the CSS variables in `styles.css`:

```css
:root {
    --primary-color: #667eea;
    --secondary-color: #764ba2;
    --success-color: #48bb78;
    --danger-color: #f56565;
    /* ... more colors ... */
}
```

### Modify Auto-Save Interval
In `app.js`, change this line:
```javascript
// Save every 5000ms (5 seconds) instead of 10000ms
this.autoSaveInterval = setInterval(() => {
    this.saveTodos();
}, 5000);
```

### Add Priority Colors
Edit the priority badge styles in `styles.css`:
```css
.priority-badge.high {
    background: #fee2e2;
    color: #991b1b;
}
```

## 🔧 Technical Details

### Class: TodoApp
Main application class handling:
- DOM manipulation
- Event handling
- Local storage operations
- Filtering and searching
- Statistics calculation

### Key Methods
- `addTodo()` - Add new task
- `deleteTodo()` - Remove task
- `toggleTodo()` - Mark complete/incomplete
- `saveTodos()` - Write to localStorage
- `loadTodos()` - Read from localStorage
- `render()` - Update UI
- `getFilteredTodos()` - Apply filters and search

### Event Handling
- Form submission for adding tasks
- Click events for filtering and deletion
- Input events for real-time search
- Page unload event for final save

## 📊 Browser Compatibility

| Browser | Support |
|---------|---------|
| Chrome | ✅ Full Support |
| Firefox | ✅ Full Support |
| Safari | ✅ Full Support |
| Edge | ✅ Full Support |
| Opera | ✅ Full Support |
| IE 11 | ⚠️ Limited (no ES6) |

## 🎯 Tips & Tricks

1. **Keyboard Shortcut**: Press Enter in the input field to add a task quickly
2. **Bulk Clear**: Use "Clear All" to reset and start fresh (careful - no undo!)
3. **Search + Filter**: Combine search with filters for powerful task finding
4. **Priority First**: Sort by high priority tasks to focus on important work
5. **Regular Cleanup**: Delete completed tasks to keep your list clean

## 📝 Future Enhancements

Potential features for expansion:
- Due dates and reminders
- Task categories/tags
- Recurring tasks
- Cloud synchronization
- Dark mode toggle
- Export/import functionality
- Undo/redo actions
- Multi-device sync

## 🐛 Troubleshooting

### Tasks Not Saving
1. Check if localStorage is enabled in your browser
2. Clear browser cache and cookies
3. Try a different browser
4. Check browser console for errors (F12)

### Data Lost After Refresh
- Verify localStorage is not being cleared on exit
- Check browser privacy settings
- Try incognito/private window mode

### UI Not Responsive
- Ensure all three files (HTML, CSS, JS) are in the same folder
- Hard refresh the page (Ctrl+F5 or Cmd+Shift+R)
- Clear browser cache

### Tasks Not Appearing
- Open browser developer tools (F12)
- Check Console tab for JavaScript errors
- Verify localStorage contains data in Application tab

## 📄 License

Free to use and modify for personal or commercial projects.

## 🎉 Enjoy!

Start organizing your tasks today! Your data stays with you - no accounts, no ads, no servers.

---

**Need help?** Check the browser console (F12 → Console tab) for any error messages.
