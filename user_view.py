import tkinter as tk
from tkinter import ttk, messagebox
from auth import authenticate, get_user_details, add_user, delete_user, get_student_grades, get_student_eca, update_student_profile
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


def login():
    username = username_entry.get()
    password = password_entry.get()

    role = authenticate(username, password)
    if role:
        user = get_user_details(username)
        if user:
            messagebox.showinfo("Login Successful", f"Welcome, {user.full_name} ({user.role})!")
            if role == "admin":
                admin_dashboard(user)
            elif role == "student":
                student_dashboard(user)
    else:
        messagebox.showerror("Login Failed", "Invalid username or password")


def admin_dashboard(user):
    def add_user_ui():
        def submit():
            new_username = username_entry.get()
            new_full_name = full_name_entry.get()
            new_password = password_entry.get()
            new_role = role_var.get()

            if add_user(new_username, new_full_name, new_password, new_role):
                messagebox.showinfo("Success", "User added successfully!")
                add_user_window.destroy()
            else:
                messagebox.showerror("Error", "Failed to add user. Username might already exist.")

        add_user_window = tk.Toplevel()
        add_user_window.title("Add User")
        add_user_window.geometry("400x350")

        form = ttk.Frame(add_user_window, padding=20)
        form.pack(expand=True)

        ttk.Label(form, text="Add New User", font=("Arial", 14, "bold")).pack(pady=10)

        ttk.Label(form, text="Username:", font=("Arial", 12)).pack(anchor="w")
        username_entry = ttk.Entry(form, font=("Arial", 12))
        username_entry.pack(fill="x", pady=5)

        ttk.Label(form, text="Full Name:", font=("Arial", 12)).pack(anchor="w")
        full_name_entry = ttk.Entry(form, font=("Arial", 12))
        full_name_entry.pack(fill="x", pady=5)

        ttk.Label(form, text="Password:", font=("Arial", 12)).pack(anchor="w")
        password_entry = ttk.Entry(form, show="*", font=("Arial", 12))
        password_entry.pack(fill="x", pady=5)

        ttk.Label(form, text="Role:", font=("Arial", 12)).pack(anchor="w")
        role_var = tk.StringVar(value="student")
        ttk.OptionMenu(form, role_var, "student", "admin", "student").pack(fill="x", pady=5)

        ttk.Button(form, text="Submit", command=submit).pack(pady=20)

    def delete_user_ui():
        def submit():
            username_to_delete = username_entry.get()
            if delete_user(username_to_delete):
                messagebox.showinfo("Success", "User deleted successfully!")
                delete_user_window.destroy()
            else:
                messagebox.showerror("Error", "Failed to delete user. Username might not exist.")

        delete_user_window = tk.Toplevel()
        delete_user_window.title("Delete User")
        delete_user_window.geometry("300x200")

        form = ttk.Frame(delete_user_window, padding=20)
        form.pack(expand=True)

        ttk.Label(form, text="Username to Delete:", font=("Arial", 12)).pack(anchor="w", pady=5)
        username_entry = ttk.Entry(form, font=("Arial", 12))
        username_entry.pack(fill="x", pady=5)

        ttk.Button(form, text="Submit", command=submit).pack(pady=20)

    admin_window = tk.Toplevel()
    admin_window.title("Admin Dashboard")
    admin_window.geometry("400x300")

    container = ttk.Frame(admin_window, padding=20)
    container.pack(expand=True)

    ttk.Label(container, text=f"Welcome, {user.full_name}!", font=("Arial", 16, "bold")).pack(pady=10)
    ttk.Separator(container).pack(fill="x", pady=10)

    ttk.Button(container, text="➕ Add User", width=30, command=add_user_ui).pack(pady=10)
    ttk.Button(container, text="🗑️ Delete User", width=30, command=delete_user_ui).pack(pady=10)


def student_dashboard(user):
    def view_details():
        grades = get_student_grades(user.username)
        eca = get_student_eca(user.username)

        details_window = tk.Toplevel()
        details_window.title("View Details")
        details_window.geometry("400x400")

        content = ttk.Frame(details_window, padding=15)
        content.pack(fill="both", expand=True)

        ttk.Label(content, text=f"Full Name: {user.full_name}", font=("Arial", 12)).pack(pady=5)
        ttk.Label(content, text=f"Role: {user.role}", font=("Arial", 12)).pack(pady=5)

        ttk.Label(content, text="Grades:", font=("Arial", 12, "bold")).pack(pady=5)
        if grades:
            for i, grade in enumerate(grades, 1):
                ttk.Label(content, text=f"Subject {i}: {grade}", font=("Arial", 12)).pack()
        else:
            ttk.Label(content, text="No grades found.", font=("Arial", 12)).pack()

        ttk.Label(content, text="ECA Activities:", font=("Arial", 12, "bold")).pack(pady=5)
        if eca:
            for activity in eca:
                ttk.Label(content, text=f"- {activity}", font=("Arial", 12)).pack()
        else:
            ttk.Label(content, text="No extracurricular activities found.", font=("Arial", 12)).pack()

    def update_profile():
        def submit():
            new_full_name = full_name_entry.get()
            if update_student_profile(user.username, new_full_name):
                messagebox.showinfo("Success", "Profile updated successfully!")
                update_window.destroy()
            else:
                messagebox.showerror("Error", "Failed to update profile.")

        update_window = tk.Toplevel()
        update_window.title("Update Profile")
        update_window.geometry("300x200")

        form = ttk.Frame(update_window, padding=15)
        form.pack(fill="both", expand=True)

        ttk.Label(form, text="New Full Name:", font=("Arial", 12)).pack(pady=5)
        full_name_entry = ttk.Entry(form, font=("Arial", 12))
        full_name_entry.insert(0, user.full_name)
        full_name_entry.pack(pady=5)

        ttk.Button(form, text="Submit", command=submit).pack(pady=10)

    def show_grades_chart():
        grades = get_student_grades(user.username)
        if not grades:
            messagebox.showinfo("No Data", "No grades found to display.")
            return

        try:
            grades = list(map(int, grades))
        except ValueError:
            messagebox.showerror("Error", "Invalid grade data format.")
            return

        subjects = [f"Subject {i+1}" for i in range(len(grades))]

        chart_window = tk.Toplevel()
        chart_window.title("Grades Chart")
        chart_window.geometry("600x400")

        fig, ax = plt.subplots(figsize=(6, 4))
        ax.bar(subjects, grades, color='skyblue')
        ax.set_title(f"{user.full_name}'s Grades")
        ax.set_xlabel("Subjects")
        ax.set_ylabel("Grades")
        ax.set_ylim(0, 100)

        for i, grade in enumerate(grades):
            ax.text(i, grade + 1, str(grade), ha='center')

        canvas = FigureCanvasTkAgg(fig, master=chart_window)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def show_eca_chart():
        eca = get_student_eca(user.username)
        if not eca:
            messagebox.showinfo("No Data", "No extracurricular activities found to display.")
            return

        activity_count = {}
        for activity in eca:
            activity_count[activity] = activity_count.get(activity, 0) + 1

        activities = list(activity_count.keys())
        counts = list(activity_count.values())

        chart_window = tk.Toplevel()
        chart_window.title("ECA Pie Chart")
        chart_window.geometry("500x400")

        fig, ax = plt.subplots(figsize=(5, 5))
        ax.pie(counts, labels=activities, autopct='%1.1f%%', startangle=90, colors=plt.cm.Paired.colors)
        ax.axis('equal')
        ax.set_title(f"{user.full_name}'s ECA Distribution")

        canvas = FigureCanvasTkAgg(fig, master=chart_window)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    student_window = tk.Toplevel()
    student_window.title("Student Dashboard")
    student_window.geometry("450x400")

    container = ttk.Frame(student_window, padding=20)
    container.pack(expand=True)

    ttk.Label(container, text=f"Welcome, {user.full_name}!", font=("Arial", 16, "bold")).pack(pady=10)
    ttk.Separator(container).pack(fill="x", pady=5)

    ttk.Button(container, text="📄 View Details", width=30, command=view_details).pack(pady=10)
    ttk.Button(container, text="✏️ Update Profile", width=30, command=update_profile).pack(pady=10)
    ttk.Button(container, text="📊 View Grades Chart", width=30, command=show_grades_chart).pack(pady=10)
    ttk.Button(container, text="🥧 View ECA Pie Chart", width=30, command=show_eca_chart).pack(pady=10)


def main():
    global username_entry, password_entry

    root = tk.Tk()
    root.title("Login System")
    root.geometry("400x300")
    root.resizable(False, False)

    style = ttk.Style()
    style.theme_use("clam")  # You can try 'alt', 'default', 'classic'

    frame = ttk.Frame(root, padding=30)
    frame.pack(expand=True)

    ttk.Label(frame, text="Username:", font=("Arial", 12)).pack(pady=10)
    username_entry = ttk.Entry(frame, font=("Arial", 12))
    username_entry.pack(fill="x")

    ttk.Label(frame, text="Password:", font=("Arial", 12)).pack(pady=10)
    password_entry = ttk.Entry(frame, show="*", font=("Arial", 12))
    password_entry.pack(fill="x")

    ttk.Button(frame, text="Login", command=login).pack(pady=20)

    root.mainloop()


if __name__ == "__main__":
    main()
