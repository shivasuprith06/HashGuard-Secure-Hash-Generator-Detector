import tkinter as tk
from tkinter import ttk
import hashlib
import base64
import re

class HashToolApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Hash Tool")

        self.tab_control = ttk.Notebook(self.root)
        self.tab_control.pack(expand=1, fill="both")

        self.hash_generator_tab = ttk.Frame(self.tab_control)
        self.hash_detector_tab = ttk.Frame(self.tab_control)

        self.tab_control.add(self.hash_generator_tab, text="Hash Generator")
        self.tab_control.add(self.hash_detector_tab, text="Hash Detector")

        self.init_hash_generator()
        self.init_hash_detector()

    def init_hash_generator(self):
        self.selected_algorithm_gen = tk.StringVar()
        self.selected_algorithm_gen.set("MD5")  # Default algorithm

        # Supported hashing algorithms
        self.algorithms = [
            "MD5", "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512",
            "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512",
             "MD4", "MD5-SHA1", 
            "SHA-3", "SHA-512/224", "SHA-512/256", "SHA-3-224", "SHA-3-256",
            "SHA-3-384", "SHA-3-512"
        ]

        # Frame for algorithm selection
        algorithm_frame = ttk.Frame(self.hash_generator_tab)
        algorithm_frame.pack(pady=10)

        ttk.Label(algorithm_frame, text="Select Algorithm:").grid(row=0, column=0, padx=5, sticky="w")
        self.algorithm_combo_gen = ttk.Combobox(algorithm_frame, textvariable=self.selected_algorithm_gen, values=self.algorithms)
        self.algorithm_combo_gen.grid(row=0, column=1, padx=5, sticky="w")

        # Frame for input and output
        input_frame = ttk.Frame(self.hash_generator_tab)
        input_frame.pack(pady=10)

        ttk.Label(input_frame, text="Input:").grid(row=0, column=0, padx=5, sticky="w")
        self.input_entry_gen = ttk.Entry(input_frame, width=40)
        self.input_entry_gen.grid(row=0, column=1, padx=5, sticky="w")

        ttk.Button(input_frame, text="Generate Hash", command=self.generate_hash).grid(row=1, column=0, columnspan=2, pady=5)

        ttk.Label(input_frame, text="Hash:").grid(row=2, column=0, padx=5, sticky="w")
        self.hash_output_gen = tk.Text(input_frame, height=4, width=40)
        self.hash_output_gen.grid(row=2, column=1, padx=5, sticky="w")

    def generate_hash(self):
        algorithm = self.selected_algorithm_gen.get()
        print("Selected Algorithm:", algorithm)  # Debug print
        print("Available Algorithms:", self.algorithms)  # Debug print
        data = self.input_entry_gen.get().encode('utf-8')

        if algorithm == "Base64":
            hash_result = base64.b64encode(data).decode('utf-8')
        elif algorithm == "MD5-SHA1":
            md5_hash = hashlib.md5(data).hexdigest()
            sha1_hash = hashlib.sha1(data).hexdigest()
            hash_result = md5_hash + sha1_hash
        elif algorithm in self.algorithms:
            hash_object = hashlib.new(algorithm)
            hash_object.update(data)
            hash_result = hash_object.hexdigest()
        else:
            hash_result = "Invalid Algorithm"

        self.hash_output_gen.delete(1.0, tk.END)
        self.hash_output_gen.insert(tk.END, hash_result)

    def init_hash_detector(self):
        self.detected_algorithm = tk.StringVar()
        self.detected_algorithm.set("")

        # Frame for algorithm selection
        algorithm_frame = ttk.Frame(self.hash_detector_tab)
        algorithm_frame.pack(pady=10)

        ttk.Label(algorithm_frame, text="Detected Algorithm:").grid(row=0, column=0, padx=5, sticky="w")
        self.algorithm_label_det = ttk.Label(algorithm_frame, textvariable=self.detected_algorithm)
        self.algorithm_label_det.grid(row=0, column=1, padx=5, sticky="w")

        # Frame for input and output
        input_frame = ttk.Frame(self.hash_detector_tab)
        input_frame.pack(pady=10)

        ttk.Label(input_frame, text="Input Hash:").grid(row=0, column=0, padx=5, sticky="w")
        self.input_entry_det = ttk.Entry(input_frame, width=40)
        self.input_entry_det.grid(row=0, column=1, padx=5, sticky="w")

        ttk.Button(input_frame, text="Detect Algorithm", command=self.detect_algorithm).grid(row=1, column=0, columnspan=2, pady=5)

    def detect_algorithm(self):
        hash_input = self.input_entry_det.get().strip()
        matched_algorithm = ""

        for algorithm in self.algorithms:
            if re.fullmatch(r'[0-9a-fA-F]+', hash_input):
                if len(hash_input) == hashlib.new(algorithm).digest_size * 2:
                    matched_algorithm = algorithm
                    break

        if matched_algorithm:
            self.detected_algorithm.set(matched_algorithm)
        else:
            self.detected_algorithm.set("Algorithm not detected")

def main():
    root = tk.Tk()
    app = HashToolApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
