/**
 * To-Do List Application with Local Storage
 * Features: Add, delete, complete tasks, filter, search, and persistent storage
 */

class TodoApp {
    constructor() {
        // Configuration
        this.AUTO_SAVE_INTERVAL = 10000; // 10 seconds
        this.STORAGE_KEY = 'todoAppData';
        
        // DOM Elements
        this.todoForm = document.getElementById('todoForm');
        this.todoInput = document.getElementById('todoInput');
        this.prioritySelect = document.getElementById('priority');
        this.todoList = document.getElementById('todoList');
        this.emptyState = document.getElementById('emptyState');
        this.searchInput = document.getElementById('searchInput');
        this.filterBtns = document.querySelectorAll('.filter-btn');
        this.clearCompletedBtn = document.getElementById('clearCompleted');
        this.clearAllBtn = document.getElementById('clearAll');
        this.totalCountEl = document.getElementById('totalCount');
        this.completedCountEl = document.getElementById('completedCount');
        this.remainingCountEl = document.getElementById('remainingCount');

        // State
        this.todos = [];
        this.currentFilter = 'all';
        this.searchTerm = '';
        this.isDirty = false;

        // Initialize
        this.init();
    }

    /**
     * Initialize the application
     */
    init() {
        this.loadFromStorage();
        this.attachEventListeners();
        this.startAutoSave();
        this.render();
    }

    /**
     * Attach all event listeners
     */
    attachEventListeners() {
        // Form submission
        this.todoForm.addEventListener('submit', (e) => this.handleAddTodo(e));

        // Search
        this.searchInput.addEventListener('input', (e) => {
            this.searchTerm = e.target.value.toLowerCase();
            this.render();
        });

        // Filters
        this.filterBtns.forEach(btn => {
            btn.addEventListener('click', (e) => {
                this.currentFilter = e.target.dataset.filter;
                this.updateFilterButtons();
                this.render();
            });
        });

        // Bulk actions
        this.clearCompletedBtn.addEventListener('click', () => this.handleClearCompleted());
        this.clearAllBtn.addEventListener('click', () => this.handleClearAll());

        // Save on unload
        window.addEventListener('beforeunload', () => {
            if (this.isDirty) {
                this.saveToStorage();
            }
        });
    }

    /**
     * Add a new todo item
     */
    handleAddTodo(e) {
        e.preventDefault();

        const text = this.todoInput.value.trim();
        const priority = this.prioritySelect.value;

        if (text === '') {
            alert('Please enter a task!');
            this.todoInput.focus();
            return;
        }

        const todo = {
            id: Date.now(),
            text: text,
            completed: false,
            priority: priority,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };

        this.todos.unshift(todo);
        this.isDirty = true;
        this.saveToStorage();

        // Reset form
        this.todoInput.value = '';
        this.prioritySelect.value = 'medium';
        this.todoInput.focus();

        this.render();
    }

    /**
     * Toggle todo completion status
     */
    toggleTodo(id) {
        const todo = this.todos.find(t => t.id === id);
        if (todo) {
            todo.completed = !todo.completed;
            todo.updatedAt = new Date().toISOString();
            this.isDirty = true;
            this.saveToStorage();
            this.render();
        }
    }

    /**
     * Delete a todo item
     */
    deleteTodo(id) {
        const todo = this.todos.find(t => t.id === id);
        if (todo && confirm(`Delete "${todo.text}"?`)) {
            this.todos = this.todos.filter(t => t.id !== id);
            this.isDirty = true;
            this.saveToStorage();
            this.render();
        }
    }

    /**
     * Clear all completed todos
     */
    handleClearCompleted() {
        const completedCount = this.todos.filter(t => t.completed).length;
        if (completedCount === 0) {
            alert('No completed tasks to clear.');
            return;
        }

        if (confirm(`Delete ${completedCount} completed task(s)?`)) {
            this.todos = this.todos.filter(t => !t.completed);
            this.isDirty = true;
            this.saveToStorage();
            this.render();
        }
    }

    /**
     * Clear all todos
     */
    handleClearAll() {
        if (this.todos.length === 0) {
            alert('No tasks to clear.');
            return;
        }

        if (confirm('Delete all tasks? This cannot be undone.')) {
            this.todos = [];
            this.isDirty = true;
            this.saveToStorage();
            this.render();
        }
    }

    /**
     * Filter todos based on current filter and search term
     */
    getFilteredTodos() {
        return this.todos.filter(todo => {
            // Apply text search
            if (this.searchTerm && !todo.text.toLowerCase().includes(this.searchTerm)) {
                return false;
            }

            // Apply status filter
            switch (this.currentFilter) {
                case 'active':
                    return !todo.completed;
                case 'completed':
                    return todo.completed;
                case 'high':
                    return todo.priority === 'high';
                default:
                    return true; // 'all'
            }
        });
    }

    /**
     * Update filter button states
     */
    updateFilterButtons() {
        this.filterBtns.forEach(btn => {
            btn.classList.toggle('active', btn.dataset.filter === this.currentFilter);
        });
    }

    /**
     * Update statistics display
     */
    updateStats() {
        const total = this.todos.length;
        const completed = this.todos.filter(t => t.completed).length;
        const remaining = total - completed;

        this.totalCountEl.textContent = total;
        this.completedCountEl.textContent = completed;
        this.remainingCountEl.textContent = remaining;
    }

    /**
     * Render the todo list
     */
    render() {
        const filteredTodos = this.getFilteredTodos();

        // Clear list
        this.todoList.innerHTML = '';

        // Show/hide empty state
        if (filteredTodos.length === 0) {
            this.emptyState.classList.add('show');
        } else {
            this.emptyState.classList.remove('show');
        }

        // Render todos
        filteredTodos.forEach(todo => {
            const li = document.createElement('li');
            li.className = `todo-item ${todo.completed ? 'completed' : ''}`;
            
            li.innerHTML = `
                <input 
                    type="checkbox" 
                    class="todo-checkbox" 
                    ${todo.completed ? 'checked' : ''}
                    onchange="todoApp.toggleTodo(${todo.id})"
                >
                <div class="todo-content">
                    <span class="todo-text">${this.escapeHtml(todo.text)}</span>
                    <span class="priority-badge ${todo.priority}">${todo.priority}</span>
                </div>
                <button class="delete-btn" onclick="todoApp.deleteTodo(${todo.id})">
                    Delete
                </button>
            `;

            this.todoList.appendChild(li);
        });

        // Update stats
        this.updateStats();
    }

    /**
     * Escape HTML special characters to prevent XSS
     */
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    /**
     * Save todos to local storage
     */
    saveToStorage() {
        try {
            localStorage.setItem(this.STORAGE_KEY, JSON.stringify(this.todos));
            this.isDirty = false;
            console.log('✅ Todos saved to storage');
        } catch (error) {
            console.error('❌ Error saving to storage:', error);
            if (error.name === 'QuotaExceededError') {
                alert('Storage quota exceeded. Please delete some tasks.');
            }
        }
    }

    /**
     * Load todos from local storage
     */
    loadFromStorage() {
        try {
            const stored = localStorage.getItem(this.STORAGE_KEY);
            if (stored) {
                this.todos = JSON.parse(stored);
                console.log(`✅ Loaded ${this.todos.length} todos from storage`);
            } else {
                console.log('📝 No saved todos found. Starting fresh.');
                this.todos = [];
            }
        } catch (error) {
            console.error('❌ Error loading from storage:', error);
            this.todos = [];
        }
    }

    /**
     * Start automatic saving interval
     */
    startAutoSave() {
        setInterval(() => {
            if (this.isDirty) {
                this.saveToStorage();
            }
        }, this.AUTO_SAVE_INTERVAL);
    }

    /**
     * Export todos as JSON (for backup)
     */
    exportData() {
        const dataStr = JSON.stringify(this.todos, null, 2);
        const dataBlob = new Blob([dataStr], { type: 'application/json' });
        const url = URL.createObjectURL(dataBlob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `todos-${new Date().toISOString().split('T')[0]}.json`;
        link.click();
        URL.revokeObjectURL(url);
    }

    /**
     * Import todos from JSON file
     */
    importData(file) {
        const reader = new FileReader();
        reader.onload = (e) => {
            try {
                const imported = JSON.parse(e.target.result);
                if (Array.isArray(imported)) {
                    if (confirm('Replace existing todos with imported data?')) {
                        this.todos = imported;
                        this.isDirty = true;
                        this.saveToStorage();
                        this.render();
                        alert('✅ Todos imported successfully!');
                    }
                } else {
                    alert('Invalid file format. Please select a valid JSON file.');
                }
            } catch (error) {
                alert('❌ Error importing file:', error.message);
            }
        };
        reader.readAsText(file);
    }
}

// Initialize the app when DOM is ready
let todoApp;
document.addEventListener('DOMContentLoaded', () => {
    todoApp = new TodoApp();
    console.log('🚀 To-Do App initialized!');
});
