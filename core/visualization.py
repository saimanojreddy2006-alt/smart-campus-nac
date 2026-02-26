import matplotlib.pyplot as plt

class Visualizer:

    def __init__(self, dataframe):
        self.df = dataframe

    def plot_login_trends(self):
        counts = self.df['login_status'].value_counts()

        plt.figure()
        plt.bar(counts.index, counts.values)
        plt.title("Login Success vs Failure")
        plt.xlabel("Login Status")
        plt.ylabel("Count")
        plt.show()