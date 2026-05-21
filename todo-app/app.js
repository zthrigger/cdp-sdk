// TODO APPLICATION WITH LOCAL STORAGE
class TodoApp {
    constructor() {
        this.todos = [];
        this.currentFilter = 'all';
        this.searchTerm = '';
        this.init();
    }

    init() {
        this.loadFromLocalStorage();
        this.setupEventListeners();
        this.render();
    }

    // ==================== LOCAL STORAGE ====================
    
    /**
     * Save todos to browser's local storage
     */
    saveToLocalStorage() {
        try {
            localStorage.setItem('todos', JSON.stringify(this.todos));
            console.log('✅ Todos saved to local storage');
        } catch (error) {
            console.error('❌ Error saving to local storage:', error);
            alert('Unable to save todos. Storage might be full.');
        }
    }

    /**
     * Load todos from browser's local storage
     */
    loadFromLocalStorage() {
        try {
            const stored = localStorage.getItem('todos');
            this.todos = stored ? JSON.parse(stored) : [];
            console.log(`✅ Loaded ${this.todos.length} todos from local storage`);
        } catch (error) {
            console.error('❌ Error loading from local storage:', error);
            this.todos = [];
        }
    }

    /**
     * Export todos as JSON file
     */
    exportTodos() {
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
    importTodos(file) {
        const reader = new FileReader();
        reader.onload = (e) => {
            try {
                const imported = JSON.parse(e.target.result);
                if (Array.isArray(imported)) {
                    this.todos = [...this.todos, ...imported];
                    this.saveToLocalStorage();
                    this.render();
                    alert('✅ Todos imported successfully!');
                } else {
                    alert('❌ Invalid file format. Please upload a valid JSON file.');
                }
            } catch (error) {
                console.error('❌ Error importing todos:', error);
                alert('❌ Error importing file. Please check the file format.');
            }
        };
        reader.readAsText(file);
    }

    // ==================== EVENT LISTENERS ====================

    setupEventListeners() {
        // Form submission
        document.getElementById('todoForm').addEventListener('submit', (e) => {
            e.preventDefault();
            this.addTodo();
        });

        // Filter buttons
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                e.target.classList.add('active');
                this.currentFilter = e.target.dataset.filter;
                this.render();
            });
        });

        // Search input
        document.getElementById('searchInput').addEventListener('input', (e) => {
            this.searchTerm = e.target.value.toLowerCase();
            this.render();
        });

        // Clear completed button
        document.getElementById('clearCompleted').addEventListener('click', () => {
            if (confirm('Are you sure you want to clear completed tasks?')) {
                this.clearCompleted();
            }
        });

        // Clear all button
        document.getElementById('clearAll').addEventListener('click', () => {
            if (confirm('Are you sure you want to delete ALL tasks? This cannot be undone!')) {
                this.clearAll();
            }
        });
    }

    // ==================== TODO OPERATIONS ====================

    /**
     * Add a new todo
     */
    addTodo() {
        const input = document.getElementById('todoInput');
        const priority = document.getElementById('priority').value;
        const text = input.value.trim();

        if (text.length === 0) {
            alert('Please enter a task!');
            return;
        }

        if (text.length > 200) {
            alert('Task is too long (max 200 characters)');
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
        this.saveToLocalStorage();
        this.render();

        // Clear inputs
        input.value = '';
        input.focus();
        document.getElementById('priority').value = 'medium';
    }

    /**
     * Toggle todo completion status
     */
    toggleTodo(id) {
        const todo = this.todos.find(t => t.id === id);
        if (todo) {
            todo.completed = !todo.completed;
            todo.updatedAt = new Date().toISOString();
            this.saveToLocalStorage();
            this.render();
        }
    }

    /**
     * Delete a todo
     */
    deleteTodo(id) {
        this.todos = this.todos.filter(t => t.id !== id);
        this.saveToLocalStorage();
        this.render();
    }

    /**
     * Clear all completed todos
     */
    clearCompleted() {
        const completedCount = this.todos.filter(t => t.completed).length;
        this.todos = this.todos.filter(t => !t.completed);
        this.saveToLocalStorage();
        this.render();
        console.log(`🗑️ Cleared ${completedCount} completed todos`);
    }

    /**
     * Clear all todos
     */
    clearAll() {
        this.todos = [];
        this.saveToLocalStorage();
        this.render();
        console.log('🗑️ All todos cleared');
    }

    // ==================== FILTERING & SEARCHING ====================

    /**
     * Get filtered todos based on current filter and search term
     */
    getFilteredTodos() {
        let filtered = this.todos;

        // Apply filter
        switch (this.currentFilter) {
            case 'active':
                filtered = filtered.filter(t => !t.completed);
                break;
            case 'completed':
                filtered = filtered.filter(t => t.completed);
                break;
            case 'high':
                filtered = filtered.filter(t => t.priority === 'high');
                break;
            case 'all':
            default:
                break;
        }

        // Apply search
        if (this.searchTerm) {
            filtered = filtered.filter(t =>
                t.text.toLowerCase().includes(this.searchTerm)
            );
        }

        return filtered;
    }

    // ==================== STATISTICS ====================

    /**
     * Update statistics
     */
    updateStats() {
        const total = this.todos.length;
        const completed = this.todos.filter(t => t.completed).length;
        const remaining = total - completed;

        document.getElementById('totalCount').textContent = total;
        document.getElementById('completedCount').textContent = completed;
        document.getElementById('remainingCount').textContent = remaining;
    }

    // ==================== RENDERING ====================

    /**
     * Render the entire application
     */
    render() {
        this.updateStats();
        this.renderTodos();
    }

    /**
     * Render todos list
     */
    renderTodos() {
        const todoList = document.getElementById('todoList');
        const emptyState = document.getElementById('emptyState');
        const filtered = this.getFilteredTodos();

        // Clear list
        todoList.innerHTML = '';

        if (filtered.length === 0) {
            emptyState.classList.add('show');
            return;
        }

        emptyState.classList.remove('show');

        // Render each todo
        filtered.forEach(todo => {
            const li = document.createElement('li');
            li.className = `todo-item ${todo.completed ? 'completed' : ''}`;

            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.className = 'todo-checkbox';
            checkbox.checked = todo.completed;
            checkbox.addEventListener('change', () => this.toggleTodo(todo.id));

            const content = document.createElement('div');
            content.className = 'todo-content';

            const text = document.createElement('span');
            text.className = 'todo-text';
            text.textContent = todo.text;
            text.title = `Created: ${new Date(todo.createdAt).toLocaleString()}`;

            const badge = document.createElement('span');
            badge.className = `priority-badge ${todo.priority}`;
            badge.textContent = todo.priority.toUpperCase();

            const deleteBtn = document.createElement('button');
            deleteBtn.className = 'delete-btn';
            deleteBtn.textContent = 'Delete';
            deleteBtn.addEventListener('click', () => {
                if (confirm('Delete this task?')) {
                    this.deleteTodo(todo.id);
                }
            });

            content.appendChild(text);
            li.appendChild(checkbox);
            li.appendChild(content);
            li.appendChild(badge);
            li.appendChild(deleteBtn);

            todoList.appendChild(li);
        });
    }
}

// ==================== INITIALIZATION ====================

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.todoApp = new TodoApp();
    console.log('🚀 Todo App Initialized');
});

// Save todos when user leaves the page
window.addEventListener('beforeunload', () => {
    if (window.todoApp) {
        window.todoApp.saveToLocalStorage();
    }
});

// Optional: Auto-save every 10 seconds
setInterval(() => {
    if (window.todoApp && window.todoApp.todos.length > 0) {
        window.todoApp.saveToLocalStorage();
    }
}, 10000);
