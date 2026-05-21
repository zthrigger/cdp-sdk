# To-Do List Application with Local Storage

A fully-featured to-do list application with persistent local storage, priority management, filtering, and search functionality.

## 🎯 Features

### Core Functionality
- ✅ **Add Tasks** - Create new tasks with text input
- ✏️ **Priority Levels** - Set Low, Medium, or High priority for each task
- ✓ **Complete Tasks** - Mark tasks as done with checkbox
- 🗑️ **Delete Tasks** - Remove individual tasks
- 💾 **Local Storage** - Persist all tasks across browser sessions

### Advanced Features
- 🔍 **Search** - Filter tasks by keyword in real-time
- 📊 **Filter Options**
  - All tasks
  - Active tasks only
  - Completed tasks only
  - High priority tasks
- 📈 **Statistics** - View total, completed, and remaining task counts
- 🧹 **Clear Actions**
  - Clear completed tasks
  - Clear all tasks (with confirmation)
- 🎨 **Responsive Design** - Works on desktop, tablet, and mobile
- ⚡ **Auto-Save** - Saves automatically every 10 seconds
- 🎭 **Visual Feedback** - Color-coded priority badges and smooth animations

## 🚀 Getting Started

### Installation

1. **Clone or download the files:**
   ```bash
   git clone <repository-url>
   cd todo-app
   ```

2. **Open in browser:**
   - Simply open `index.html` in your web browser
   - No server or dependencies required!

### File Structure

```
todo-app/
├── index.html      # HTML structure and layout
├── styles.css      # Styling and responsive design
├── app.js          # Application logic and local storage
└── README.md       # Documentation (this file)
```

## 💻 How to Use

### Adding a Task
1. Type your task in the input field
2. Select priority level (Low, Medium, High)
3. Click "Add Task" or press Enter
4. Task appears at the top of the list

### Managing Tasks
- **Mark Complete:** Click the checkbox next to a task
- **Search:** Type in the search box to filter tasks
- **Delete:** Click the "Delete" button on any task
- **Filter:** Use the filter buttons to show specific task types

### Clearing Tasks
- **Clear Completed:** Removes all finished tasks
- **Clear All:** Removes every task (requires confirmation)

## 💾 Local Storage

### How It Works

The app uses the browser's **LocalStorage API** to persist data:

```javascript
// Save to local storage
localStorage.setItem('todos', JSON.stringify(this.todos));

// Load from local storage
const stored = localStorage.getItem('todos');
this.todos = stored ? JSON.parse(stored) : [];
```

### Storage Details

- **Key:** `todos`
- **Value:** JSON array of todo objects
- **Capacity:** ~5-10MB per domain (browser dependent)
- **Persistence:** Data survives browser restarts and refreshes

### Todo Object Structure

```javascript
{
  id: 1234567890,              // Unique identifier (timestamp)
  text: "Learn JavaScript",     // Task description
  completed: false,            // Completion status
  priority: "high",            // Priority level
  createdAt: "2024-01-15T...", // ISO timestamp
  updatedAt: "2024-01-15T..."  // Last update timestamp
}
```

### Auto-Save Features

- **On Every Change:** Saves when you add, complete, or delete a task
- **On Page Leave:** Saves when you close or navigate away
- **Periodic:** Auto-saves every 10 seconds as a safety backup

## 🔧 API Reference

### Public Methods

#### `addTodo()`
Adds a new task from the input field.

```javascript
todoApp.addTodo();
```

#### `toggleTodo(id)`
Toggles the completion status of a task.

```javascript
todoApp.toggleTodo(1234567890);
```

#### `deleteTodo(id)`
Deletes a specific task.

```javascript
todoApp.deleteTodo(1234567890);
```

#### `clearCompleted()`
Removes all completed tasks.

```javascript
todoApp.clearCompleted();
```

#### `clearAll()`
Removes all tasks.

```javascript
todoApp.clearAll();
```

#### `saveToLocalStorage()`
Manually saves todos to local storage.

```javascript
todoApp.saveToLocalStorage();
```

#### `loadFromLocalStorage()`
Manually loads todos from local storage.

```javascript
todoApp.loadFromLocalStorage();
```

#### `getFilteredTodos()`
Returns filtered todos based on current filter and search.

```javascript
const filtered = todoApp.getFilteredTodos();
```

#### `exportTodos()`
Exports all todos as a JSON file.

```javascript
todoApp.exportTodos();
```

#### `importTodos(file)`
Imports todos from a JSON file.

```javascript
todoApp.importTodos(fileInput.files[0]);
```

## 🎨 Styling

### Color Scheme

- **Primary:** `#3498db` (Blue) - Main actions
- **Secondary:** `#2ecc71` (Green) - Success states
- **Danger:** `#e74c3c` (Red) - Delete/destructive
- **Warning:** `#f39c12` (Orange) - Clear completed
- **Gradient:** Purple gradient for header and buttons

### Priority Badge Colors

- **High:** Red background (#ffe6e6)
- **Medium:** Yellow background (#fff3cd)
- **Low:** Green background (#d4edda)

### Responsive Breakpoints

- **Desktop:** Full layout (600px max-width)
- **Tablet:** Adjusted spacing and font sizes
- **Mobile:** Stacked layout, smaller fonts
- **Extra Small:** Further optimizations for < 320px

## 🐛 Troubleshooting

### Tasks Not Saving?
- Check if LocalStorage is enabled in your browser
- Verify browser isn't in private/incognito mode (limited storage)
- Check browser console for errors (F12 → Console)

### Tasks Disappeared?
- Browser cache was cleared
- LocalStorage quota exceeded (very rare)
- Browser doesn't support LocalStorage (very old browsers)

### Performance Issues?
- Works smoothly with 100+ tasks
- For extreme cases (1000+ tasks), consider implementing pagination

## 📱 Browser Compatibility

| Browser | Support |
|---------|---------|
| Chrome/Edge | ✅ Full support |
| Firefox | ✅ Full support |
| Safari | ✅ Full support |
| Opera | ✅ Full support |
| IE 8+ | ✅ LocalStorage support |

## 🔐 Security Notes

- All data is stored **locally** in your browser
- No data is sent to any server
- No personal information is collected
- You have complete control over your data

## 🚀 Future Enhancements

Possible features for future versions:

- 📅 Due dates and reminders
- 🏷️ Categories/tags
- 🔔 Browser notifications
- 📊 Data analytics and charts
- ☁️ Cloud sync across devices
- 🎯 Recurring tasks
- 🎨 Custom themes
- 📝 Rich text editor
- ⏰ Pomodoro timer integration
- 🔄 Undo/Redo functionality

## 📄 License

This project is open source and available for personal and educational use.

## 🤝 Contributing

Feel free to fork, modify, and improve this application!

## 📞 Support

If you encounter any issues:

1. Check the browser console (F12 → Console) for error messages
2. Clear browser cache and try again
3. Test in a different browser
4. Check this README's troubleshooting section

---

**Made with ❤️ by a developer who loves productivity tools**
